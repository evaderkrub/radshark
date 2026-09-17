// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Dave Robins

// Exercise the real Npcap source with locally generated UDP, without an adapter
// or Intrepid device. A machine without Npcap loopback reports a skip.
#include <winsock2.h>
#include "sources.h"
#include <chrono>
#include <iostream>
#include <thread>
int main() {
    std::string id;
    for(const auto& source:radshark::ListLocalInterfaces())
        if(source.id.find("NPF_Loopback")!=std::string::npos) id=source.id;
    if(id.empty()) {std::cout<<"Npcap loopback is unavailable\n";return 125;}
    WSADATA data{};if(WSAStartup(MAKEWORD(2,2),&data))return 1;
    const SOCKET socketfd=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    if(socketfd==INVALID_SOCKET) {WSACleanup();return 1;}
    auto source=radshark::OpenLocalInterface(id,false,"udp and dst port 45178");
    std::string error;
    if(!source->start(error)) {std::cerr<<error;closesocket(socketfd);WSACleanup();return 1;}
    sockaddr_in destination{};destination.sin_family=AF_INET;destination.sin_port=htons(45178);destination.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    const std::string payload="RadShark loopback capture verification";
    std::vector<radshark::RawFrame> frames;
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
    while(frames.empty() && std::chrono::steady_clock::now()<deadline) {
        sendto(socketfd,payload.data(),static_cast<int>(payload.size()),0,reinterpret_cast<const sockaddr*>(&destination),sizeof destination);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));source->poll(frames);
    }
    source->stop();closesocket(socketfd);WSACleanup();
    bool found=false;
    for(const auto& frame:frames) {
        const std::string bytes(frame.bytes.begin(),frame.bytes.end());
        found|=bytes.find(payload)!=std::string::npos && frame.has_ts;
    }
    if(!found || source->running()) {std::cerr<<"Loopback packet was not captured or capture did not stop\n";return 1;}
    std::cout<<"Npcap captured the generated UDP payload and stopped successfully ("<<frames.size()<<" frame(s))\n";
    return 0;
}
