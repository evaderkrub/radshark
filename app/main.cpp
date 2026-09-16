// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Dave Robins

#include "analyzer.h"
#include "portable_ui.h"
#include "sources.h"
#include <SDL3/SDL.h>
#include <SDL3/SDL_main.h>
#include <imgui_impl_sdl3.h>
#include <imgui_impl_sdlrenderer3.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#ifdef IMGUI_ENABLE_TEST_ENGINE
#include "ui_tests.h"
#include <imgui_te_engine.h>
#include <imgui_te_coroutine.h>
#include <imgui_te_exporters.h>
#endif
namespace fs=std::filesystem;
int main(int argc,char** argv) {
    bool test=false,list=false; int frames=0,width=1400,height=900;
    std::string open,screenshot;
    for(int i=1;i<argc;++i) {
        const std::string arg=argv[i];
        if(arg=="--test") test=true;
        else if(arg=="--list-sources") list=true;
        else if(arg=="--open" && i+1<argc) open=argv[++i];
        else if(arg=="--screenshot" && i+1<argc) screenshot=argv[++i];
        else if(arg=="--frames" && i+1<argc) frames=std::stoi(argv[++i]);
        else if(arg=="--width" && i+1<argc) width=std::stoi(argv[++i]);
        else if(arg=="--height" && i+1<argc) height=std::stoi(argv[++i]);
        else { std::cerr<<"Usage: vspyshark [--open capture.pcap] [--list-sources] [--test] [--screenshot path.png --frames N] [--width N --height N]\n";return 2; }
    }
    if(list) {
        auto sources=vspyshark::ListLocalInterfaces();auto devices=vspyshark::ListIcsneoDevices(true);
        sources.insert(sources.end(),devices.begin(),devices.end());
        auto rows=nlohmann::json::array();
        for(const auto& s:sources) rows.push_back({{"kind",vspyshark::SourceKindName(s.kind)},{"id",s.id},{"name",s.name},{"available",s.available},{"reason",s.reason}});
        std::cout<<nlohmann::json{{"pcap",vspyshark::LocalCaptureAvailable()},{"libicsneo",vspyshark::IcsneoAvailable()},{"sources",rows}}.dump(2)<<'\n';return 0;
    }
#ifndef IMGUI_ENABLE_TEST_ENGINE
    if(test) { std::cerr<<"Rebuild with VSPYSHARK_TEST_ENGINE=ON to run UI tests\n";return 2; }
#endif
    if(!SDL_Init(SDL_INIT_VIDEO)) {std::cerr<<SDL_GetError();return 1;}
    SDL_Window* window=SDL_CreateWindow("VSpy Shark",width,height,SDL_WINDOW_RESIZABLE|SDL_WINDOW_HIGH_PIXEL_DENSITY);
    SDL_Renderer* renderer=window?SDL_CreateRenderer(window,nullptr):nullptr;
    if(!renderer) {std::cerr<<SDL_GetError();SDL_Quit();return 1;}
    SDL_SetRenderVSync(renderer,1);
    IMGUI_CHECKVERSION();ImGui::CreateContext();
    auto& io=ImGui::GetIO();io.ConfigFlags|=ImGuiConfigFlags_NavEnableKeyboard;
    ImGui::StyleColorsLight();
    ImGui::GetStyle().WindowRounding=0;ImGui::GetStyle().FrameRounding=3;
    ImFont* regular=nullptr;ImFont* mono=nullptr;ImFont* bold=nullptr;
#ifdef _WIN32
    regular=io.Fonts->AddFontFromFileTTF("C:/Windows/Fonts/segoeui.ttf",16);
    mono=io.Fonts->AddFontFromFileTTF("C:/Windows/Fonts/consola.ttf",15);
    bold=io.Fonts->AddFontFromFileTTF("C:/Windows/Fonts/segoeuib.ttf",16);
#endif
    if(!regular) regular=io.Fonts->AddFontDefault();
    if(!mono) mono=regular;if(!bold) bold=regular;
    io.FontDefault=regular;
    const bool persist=!test && frames==0;
    char* pref=SDL_GetPrefPath("IntrepidCS","VSpyShark");
    const fs::path prefdir=pref?fs::u8path(pref):fs::current_path();SDL_free(pref);
    const std::string ini=(prefdir/"imgui.ini").string();io.IniFilename=persist?ini.c_str():nullptr;
    std::map<std::string,std::string> settings;
    if(persist) {std::ifstream f(prefdir/"settings.json");if(f)try{settings=nlohmann::json::parse(f).get<decltype(settings)>();}catch(const std::exception& e){std::cerr<<"Settings: "<<e.what()<<'\n';}}
    ImGui_ImplSDL3_InitForSDLRenderer(window,renderer);ImGui_ImplSDLRenderer3_Init(renderer);
    int result=0;
    {
        vspyshark::PortableUi ui;
        vspyshark::Services services;ui.Bind(services);
        services.settings_get=[&](const char* k)->std::string_view {auto it=settings.find(k);return it==settings.end()?std::string_view():it->second;};
        services.settings_set=[&](const char* k,const char* v){settings[k]=v;};
        services.log=[](int,const std::string& s){std::cerr<<s<<'\n';};
        services.push_font=[&](vspyshark::Font f){ImGui::PushFont(f==vspyshark::Font::Mono?mono:bold);};
        services.pop_font=[](){ImGui::PopFont();};
        vspyshark::Analyzer analyzer;analyzer.Init(services);
#ifdef IMGUI_ENABLE_TEST_ENGINE
        auto* engine=ImGuiTestEngine_CreateContext();auto& testio=ImGuiTestEngine_GetIO(engine);
        testio.ConfigLogToTTY=true;testio.ConfigRunSpeed=ImGuiTestRunSpeed_Fast;
        testio.ConfigVerboseLevel=ImGuiTestVerboseLevel_Debug;
        testio.ConfigVerboseLevelOnError=ImGuiTestVerboseLevel_Debug;
        testio.CoroutineFuncs=Coroutine_ImplStdThread_GetInterface();
        if(test) {
            testio.ExportResultsFilename="uitest_results_junit.xml";
            testio.ExportResultsFormat=ImGuiTestEngineExportFormat_JUnitXml;
        }
        SharkUiTests teststate{&analyzer};RegisterSharkTests(engine,teststate);
        ImGuiTestEngine_Start(engine,ImGui::GetCurrentContext());
        if(test) ImGuiTestEngine_QueueTests(engine,ImGuiTestGroup_Tests,"shark",ImGuiTestRunFlags_None);
#endif
        bool done=false;int frame=0;
        while(!done) {
            SDL_Event event;while(SDL_PollEvent(&event)) {
                ImGui_ImplSDL3_ProcessEvent(&event);
                if(event.type==SDL_EVENT_QUIT || (event.type==SDL_EVENT_WINDOW_CLOSE_REQUESTED && event.window.windowID==SDL_GetWindowID(window))) done=true;
                if(event.type==SDL_EVENT_DROP_FILE) open=event.drop.data;
            }
            analyzer.Frame();
            ImGui_ImplSDLRenderer3_NewFrame();ImGui_ImplSDL3_NewFrame();ImGui::NewFrame();
            ImGui::SetNextWindowPos(ImVec2(0,0));ImGui::SetNextWindowSize(io.DisplaySize);
            ImGui::Begin("VSpy Shark###SharkMain",nullptr,ImGuiWindowFlags_NoTitleBar|ImGuiWindowFlags_NoResize|ImGuiWindowFlags_NoMove|ImGuiWindowFlags_NoCollapse|ImGuiWindowFlags_NoScrollbar|ImGuiWindowFlags_MenuBar);
            analyzer.Draw();ui.Draw();ImGui::End();
            if(!open.empty()) {std::string error;if(!analyzer.View().OpenFile(services,open,error)){std::cerr<<error<<'\n';result=1;}open.clear();}
            ImGui::Render();SDL_SetRenderDrawColor(renderer,245,245,245,255);SDL_RenderClear(renderer);
            ImGui_ImplSDLRenderer3_RenderDrawData(ImGui::GetDrawData(),renderer);
            std::string shot;
#ifdef IMGUI_ENABLE_TEST_ENGINE
            shot=std::move(teststate.screenshot);teststate.screenshot.clear();
#endif
            if(frames>0 && frame+1>=frames) {shot=screenshot;done=true;}
            if(!shot.empty()) {auto* pixels=SDL_RenderReadPixels(renderer,nullptr);if(!pixels||!SDL_SavePNG(pixels,shot.c_str())){std::cerr<<SDL_GetError();result=1;}SDL_DestroySurface(pixels);}
            SDL_RenderPresent(renderer);++frame;
#ifdef IMGUI_ENABLE_TEST_ENGINE
            ImGuiTestEngine_PostSwap(engine);
            if(test && frame>5 && ImGuiTestEngine_IsTestQueueEmpty(engine)) {
                int tested=0,passed=0;ImGuiTestEngine_GetResult(engine,tested,passed);
                std::ofstream("uitest_results.txt")<<"shark: "<<passed<<'/'<<tested<<" passed\n";
                std::cout<<"shark: "<<passed<<'/'<<tested<<" passed\n";
                if(tested!=3 || passed!=tested) result=1;done=true;
            }
#endif
        }
        analyzer.Shutdown();
#ifdef IMGUI_ENABLE_TEST_ENGINE
        ImGuiTestEngine_Stop(engine);ImGuiTestEngine_DestroyContext(engine);
#endif
        if(persist) {
            const auto temp=prefdir/"settings.json.tmp";
            {std::ofstream f(temp);f<<nlohmann::json(settings).dump(2);}
            std::error_code ec;fs::rename(temp,prefdir/"settings.json",ec);
#ifdef _WIN32
            if(ec) {fs::copy_file(temp,prefdir/"settings.json",fs::copy_options::overwrite_existing,ec);if(!ec)fs::remove(temp,ec);}
#endif
        }
    }
    ImGui_ImplSDLRenderer3_Shutdown();ImGui_ImplSDL3_Shutdown();ImGui::DestroyContext();
    SDL_DestroyRenderer(renderer);SDL_DestroyWindow(window);SDL_Quit();return result;
}
