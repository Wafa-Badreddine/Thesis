# Thesis#include "RoutGeo5.h"

#include <cassert>

#include "NetwPkt_m.h"
#include "NetwControlInfo.h"

#include "singleton.h"

using std::endl;

Define_Module(RoutGeo5);

void RoutGeo5::initialize(int stage) {
    BaseNetwLayer::initialize(stage);

    if (stage == 1)
    {
        seqNum = 0;
        nbDataPacketsReceived = 0;
        nbDataPacketsSent = 0;
        nbDataPacketsForwarded = 0;

        nbHops = 0;
        MaxNbHops = 0;

        dataReceived=0;

        hasPar("defaultTtl") ? defaultTtl = par("defaultTtl") : defaultTtl = 4;
        EV<< "defaultTtl = " << defaultTtl<< endl;

        hasPar("bcMaxEntries") ? bcMaxEntries = par("bcMaxEntries") : bcMaxEntries = 6;

        hasPar("bcDelTime") ? bcDelTime = par("bcDelTime") : bcDelTime = 180.0;
        EV <<"bcMaxEntries = "<<bcMaxEntries <<" bcDelTime = "<<bcDelTime<<endl;
    }
}

void RoutGeo5::finish() {
    bcMsgs.clear();
        cOwnedObject *Del=NULL;
                        int OwnedSize=this->defaultListSize();
                        for(int i=0;i<OwnedSize;i++){
                                Del=this->defaultListGet(0);
                                this->drop(Del);
                                delete Del;
                        }

    recordScalar("nbDataPacketsReceived", nbDataPacketsReceived);
    recordScalar("nbDataPacketsSent", nbDataPacketsSent);
    recordScalar("nbDataPacketsForwarded", nbDataPacketsForwarded);
    recordScalar("dataReceived", dataReceived);
    recordScalar("AllmsgReceived",AllmsgReceived);

    recordScalar("NodeNumber", myNetwAddr);


    if (nbDataPacketsReceived > 0) {
      recordScalar("meanNbHops", (double) nbHops / (double) nbDataPacketsReceived);
    } else {
        recordScalar("meanNbHops", 0);
    }
    recordScalar("MaxNbHops", MaxNbHops);
}

void RoutGeo5::handleUpperMsg(cMessage* m) {

    assert(dynamic_cast<cPacket*> (m));
    NetwPkt *msg = encapsMsg(static_cast<cPacket*> (m));

    msg->setSeqNum(seqNum);
    seqNum++;
    msg->setTtl(defaultTtl);
    msg->setInitialsrcAddr(myNetwAddr);
    msg->setSrcAddr(myNetwAddr);
    msg->setFinaldestAddr(1);
    msg->setDestAddr(LAddress::L3BROADCAST);

    sendDown(msg);

    nbDataPacketsSent++;
}

void RoutGeo5::handleLowerMsg(cMessage* m)
{
    NetwPkt *msg = static_cast<NetwPkt *> (m);

    AllmsgReceived++;

    dataReceived++;

    if(msg->getFinaldestAddr()==myNetwAddr)
    {
        if(notBroadcasted(msg))
        {
            nbDataPacketsReceived++;
            EV<<"je suis "<<myNetwAddr<< " et j'ai reçu des données de "<< msg->getInitialsrcAddr()<< " à travers "<<msg->getSrcAddr()<<endl;
            msg->setSrcAddr(msg->getInitialsrcAddr());
            nbHops = nbHops + (defaultTtl-msg->getTtl());

            if ((defaultTtl-msg->getTtl()) > MaxNbHops)
                MaxNbHops = (defaultTtl-msg->getTtl());

            sendUp(decapsMsg(msg) );
        }
        else
        {
            EV<<"je suis "<<myNetwAddr<< " et j'ai déjà reçu ce message de "<< msg->getInitialsrcAddr()<< " à travers "<<msg->getSrcAddr()<<endl;
            delete msg;
        }
    }
    else
    {
            if( msg->getTtl() > 1 )
            {
                EV <<" data msg BROADCAST! ttl = "<<msg->getTtl()
                <<" > 1 -> rebroadcast msg \n";
                msg->setSrcAddr(myNetwAddr);
                msg->setTtl( msg->getTtl()-1 );
                msg->removeControlInfo();
                setDownControlInfo(msg, LAddress::L2BROADCAST);
                sendDown( msg );
                nbDataPacketsForwarded++;
            }
            else
            {
                EV<<" TTL = "<<msg->getTtl()<<endl;
                delete msg;
            }
    }

}

bool RoutGeo5::notBroadcasted(NetwPkt* msg) {

    cBroadcastList::iterator it;

    //serach the broadcast list of outdated entries and delete them
    for (it = bcMsgs.begin(); it != bcMsgs.end(); it++) {
        if (it->delTime < simTime()) {
            bcMsgs.erase(it);
            it--;
        }
        //message was already broadcasted
        if ((it->srcAddr == msg->getInitialsrcAddr()) && (it->seqNum
                == msg->getSeqNum())) {
            // update entry
            it->delTime = simTime() + bcDelTime;
            return false;
        }
    }

    //delete oldest entry if max size is reached
    if (bcMsgs.size() >= bcMaxEntries) {
        EV<<"bcMsgs is full, delete oldest entry\n";
        bcMsgs.pop_front();
    }

    bcMsgs.push_back(Bcast(msg->getSeqNum(), msg->getInitialsrcAddr(), simTime() +bcDelTime));
    return true;
}

NetwPkt* RoutGeo5::encapsMsg(cPacket *appPkt) {
    LAddress::L2Type macAddr;
    LAddress::L3Type netwAddr;

    EV<<"in encaps...\n";

    NetwPkt *pkt = new NetwPkt(appPkt->getName(), appPkt->getKind());
    pkt->setBitLength(headerLength);

    cObject* cInfo = appPkt->removeControlInfo();

    if(cInfo == NULL){
    EV << "warning: Application layer did not specifiy a destination L3 address\n"
       << "\tusing broadcast address instead\n";
    netwAddr = LAddress::L3BROADCAST;
    } else {
    EV <<"CInfo removed, netw addr="<< NetwControlInfo::getAddressFromControlInfo( cInfo ) <<endl;
        netwAddr = NetwControlInfo::getAddressFromControlInfo( cInfo );
    delete cInfo;
    }

    pkt->setSrcAddr(myNetwAddr);
    pkt->setDestAddr(netwAddr);
    EV << " netw "<< myNetwAddr << " sending packet" <<endl;

    EV << "sendDown: nHop=L3BROADCAST -> message has to be broadcasted"
       << " -> set destMac=L2BROADCAST" << endl;
    macAddr = LAddress::L2BROADCAST;

    setDownControlInfo(pkt, macAddr);

    //encapsulate the application packet
    pkt->encapsulate(appPkt);
    EV <<" pkt encapsulated\n";
    return pkt;
}
