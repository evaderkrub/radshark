// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Dave Robins

#include "ui_tests.h"
#include "sources.h"
#include <imgui_internal.h>
#include <imgui_te_engine.h>
#include <imgui_te_context.h>
#include <chrono>
namespace {
SharkUiTests& State(ImGuiTestContext* ctx) { return *static_cast<SharkUiTests*>(ctx->Test->UserData); }
bool Wait(ImGuiTestContext* ctx,const std::function<bool()>& predicate) {
    const auto end=std::chrono::steady_clock::now()+std::chrono::seconds(15);
    while(!predicate() && std::chrono::steady_clock::now()<end) ctx->Yield();
    return predicate();
}
void Ref(ImGuiTestContext* ctx) { ctx->SetRef(ImGui::FindWindowByName("VSpy Shark###SharkMain")->ID); }
}
void RegisterSharkTests(ImGuiTestEngine* engine,SharkUiTests& state) {
    auto* t=IM_REGISTER_TEST(engine,"shark","welcome");t->UserData=&state;
    t->TestFunc=[](ImGuiTestContext* ctx){
        ctx->Yield(5);Ref(ctx);
        IM_CHECK(ctx->ItemInfo("###cs_options").ID!=0);
        IM_CHECK(ctx->ItemInfo("###cs_open").ID!=0);
        auto& a=*State(ctx).analyzer;
        IM_CHECK(a.View().capture().Decoder().ready);
        const auto sources=a.View().AllSources(a.Host(),false);
        bool local=false,device=false;
        for(const auto& e:sources) {
            local|=e.kind==vspyshark::SourceKind::LocalInterface;
            device|=e.kind==vspyshark::SourceKind::Icsneo;
            IM_CHECK(e.kind!=vspyshark::SourceKind::Corelib && e.kind!=vspyshark::SourceKind::Libx);
        }
        IM_CHECK(local); IM_CHECK(device);
        State(ctx).screenshot="shark-welcome.png";ctx->Yield(3);
        ctx->ItemClick("###cs_options");ctx->Yield(3);
        auto* options=ImGui::FindWindowByName("Capture Options###cs_capopts");IM_CHECK(options!=nullptr);
        ctx->SetRef(options->ID);ctx->ItemClick("###cs_capopts_close");ctx->Yield(2);
    };
    t=IM_REGISTER_TEST(engine,"shark","file_details_filters");t->UserData=&state;
    t->TestFunc=[](ImGuiTestContext* ctx){
        auto& a=*State(ctx).analyzer; std::string error;
        IM_CHECK(a.View().OpenFile(a.Host(),SHARK_SAMPLE_PCAP,error));
        IM_CHECK(Wait(ctx,[&]{return a.View().capture().Count()==16 && a.View().capture().PendingCount()==0;}));
        auto& cap=a.View().capture();IM_CHECK_EQ(cap.DecodedCount(),16);
        const int protocol=cap.ColumnIndex("Protocol");IM_CHECK(protocol>=0);
        IM_CHECK(cap.At(0).cols[protocol]=="ARP");
        a.View().Select(6);
        IM_CHECK(Wait(ctx,[&]{return cap.Tree(6)!=nullptr;}));
        IM_CHECK(!cap.Tree(6)->children.empty());
        State(ctx).screenshot="shark-packets.png";ctx->Yield(3);
        Ref(ctx);ctx->ItemInputValue("###cs_filter","tcp");ctx->KeyPress(ImGuiKey_Enter);
        IM_CHECK(Wait(ctx,[&]{return cap.Filter()=="tcp" && cap.FilterStatus()==vspyshark::Capture::FilterState::Valid && cap.PendingCount()==0;}));
        IM_CHECK(cap.Displayed().size()>0 && cap.Displayed().size()<16);
        IM_CHECK(a.View().SaveAs("shark-export.pcapng",true,error));
        wirespy::PcapFile saved;IM_CHECK(wirespy::ReadPcap("shark-export.pcapng",saved));
        IM_CHECK_EQ(saved.frames.size(),cap.Displayed().size());
        Ref(ctx);ctx->ItemClick("###cs_filter_clear");
        IM_CHECK(Wait(ctx,[&]{return cap.PendingCount()==0 && cap.Displayed().size()==16;}));
        a.View().StopCapture();
    };
    t=IM_REGISTER_TEST(engine,"shark","file_browser");t->UserData=&state;
    t->TestFunc=[](ImGuiTestContext* ctx){
        Ref(ctx);ctx->ItemClick("###cs_open");ctx->Yield(3);
        auto* dialog=ImGui::FindWindowByName("Capture file###shark_file");IM_CHECK(dialog!=nullptr);
        ctx->SetRef(dialog->ID);ctx->ItemInputValue("###shark_filename",SHARK_SAMPLE_PCAP);
        ctx->ItemClick("Open");ctx->Yield(3);
        auto& a=*State(ctx).analyzer;
        IM_CHECK(Wait(ctx,[&]{return a.View().capture().Count()==16 && a.View().capture().PendingCount()==0;}));
        IM_CHECK(a.View().FilePath()==SHARK_SAMPLE_PCAP);
        a.View().StopCapture();
    };
}
