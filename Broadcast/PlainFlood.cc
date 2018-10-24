
#include "PlainFlood.h"
#include "singleton.h"
#include <cassert>
#include "NetwPkt_m.h"
#include "NetwControlInfo.h"


using std::endl;

Define_Module(PlainFlood);

/**
 * Reads all parameters from the ini file. If a parameter is not
 * specified in the ini file a default value will be set.
 **/

void PlainFlood::initialize(int stage) {
    BaseNetwLayer::initialize(stage);

    if (stage == 0) {

        nbDataPacketsReceived = 0; // Incremented each time a packet is received for the first time.
        nbDataPacketsSent = 0; // Incremented each time a packet from application layer is sent for the first time.
        nbDataPacketsForwarded = 0; //Incremented each time a packet is forwarded

        nbHops = 0; // computed when a new packet is received
        MaxNbHops =0;
        dataReceived=0; // All received packets including redundant ones

        //For de-sequencing
        Deseqence0=0;
        Deseqence2=0;
        Deseqence3=0;
        Deseqence4=0;
        Deseqence5=0;
        Deseqence6=0;
        nbDesquence=0;

        hasPar("defaultTtl") ? defaultTtl = par("defaultTtl") : defaultTtl = 6;
        EV<< "defaultTtl = " << defaultTtl<< endl;

        hasPar("bcMaxEntries") ? bcMaxEntries = par("bcMaxEntries") : bcMaxEntries = 10000;

        hasPar("bcDelTime") ? bcDelTime = par("bcDelTime") : bcDelTime = 180.0;
        EV <<"bcMaxEntries = "<<bcMaxEntries <<" bcDelTime = "<<bcDelTime<<endl;

    }
}

void PlainFlood::finish()
{
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
    recordScalar("nbDesquence", nbDesquence);
    recordScalar("NodeNumber", myNetwAddr);

    //computes the average msg's number of hops
    if (nbDataPacketsReceived > 0) {
      recordScalar("meanNbHops", (double) nbHops / (double) nbDataPacketsReceived);
    } else {
        recordScalar("meanNbHops", 0);
    }
    recordScalar("MaxNbHops", MaxNbHops);
}

 /**
 * Fields as Sequence number and TTL have to be specified.
 * Afterwards messages can be handed to the MAC layer.
 * In case of plain flooding, using the message sequence number and
 * source address stored in the bcMsgs list, the message will not be re-broadcasted,
 * if a copy is flooded back from neighboring nodes.
 **/

void PlainFlood::handleUpperMsg(cMessage* m)
{
    assert(dynamic_cast<cPacket*> (m));
    NetwPkt *msg = encapsMsg(check_and_cast<cPacket*> (m));

    msg->setSeqNum(seqNum);
    seqNum++;
    msg->setTtl(defaultTtl);
    msg->setForwAddr(myNetwAddr);
    msg->setSrcAddr(myNetwAddr);

    // Record broadcasted packets
    bcMsgs.push_back(Bcast(msg->getSeqNum(), msg->getSrcAddr(), simTime()+bcDelTime));

    // Write to the Log File the following informations
    SoundManager& ptr1=SoundManager::Instance();
    ptr1.Instance().fwrite(simTime(),myNetwAddr,msg->getForwAddr(),msg->getSeqNum(),msg->getTtl());

    //there is no routing so all messages are broadcasted to the MAC layer
    sendDown(msg);

    nbDataPacketsSent++;
}


void PlainFlood::handleLowerMsg(cMessage* m)
{
    NetwPkt *msg = check_and_cast<NetwPkt *> (m);

    // Write to the Log File the following informations
    SoundManager& ptr1=SoundManager::Instance();
    ptr1.Instance().fwrite(simTime(),myNetwAddr,msg->getForwAddr(),msg->getSeqNum(),(msg->getTtl()-1));

    // a broadcast msg
    if(LAddress::isL3Broadcast(msg->getDestAddr()))
        {
        dataReceived++;

        if (notBroadcasted(msg))
            {
            nbHops = nbHops + (defaultTtl - msg->getTtl());

            if ((defaultTtl-msg->getTtl()) > MaxNbHops)
            MaxNbHops = (defaultTtl-msg->getTtl());

            //check ttl and rebroadcast
            if( msg->getTtl() > 1 )
            {
                NetwPkt *dMsg;
                EV <<" data msg BROADCAST! ttl = "<<msg->getTtl()<<" > 1 -> rebroadcast msg & send to upper\n";
                msg->setTtl( msg->getTtl()-1 );
                msg->setForwAddr(myNetwAddr);
                dMsg = msg->dup();
                dMsg->removeControlInfo();
                setDownControlInfo(dMsg, LAddress::L2BROADCAST);
                sendDown( dMsg );
                nbDataPacketsForwarded++;
            }
            else
            EV <<" TTL = "<<msg->getTtl()<<" -> only send to upper\n";

            // message has to be forwarded to upper layer
            sendUp(decapsMsg(msg) );
            nbDataPacketsReceived++;
            }
        // Already broadcasted
         else
           {
            EV <<" i already broadcasted this msg -> delete msg\n";
            delete msg;
           }

        }
}

/**
 * The bcMsgs list is searched for the arrived message.
 * If the message is in the list, it was already broadcasted
 * and the function returns false.
 **/

bool PlainFlood::notBroadcasted(NetwPkt* msg)
{
    cBroadcastList::iterator it;

    //search the broadcast list
    for (it = bcMsgs.begin(); it != bcMsgs.end(); it++)
    {
        //message was already broadcasted
        if ((it->srcAddr == msg->getSrcAddr()) && (it->seqNum == msg->getSeqNum()))
        {
            // update entry
            it->delTime = simTime() + bcDelTime;
            return false;
        }
    }

    bcMsgs.push_back(Bcast(msg->getSeqNum(), msg->getSrcAddr(), simTime() +bcDelTime));

    /// code de-sequencing
      switch (myNetwAddr)
          {
          case 0 :
              if((int)msg->getSeqNum() < Deseqence0)
              {
                  nbDesquence++;
              }
              Deseqence0=msg->getSeqNum();
              break;
          case 2 :
              if((int)msg->getSeqNum() < Deseqence2)
              {
                  nbDesquence++;
              }
              Deseqence2=msg->getSeqNum();
              break;
          case 3 :
              if((int)msg->getSeqNum() < Deseqence3)
              {
                  nbDesquence++;
              }
              Deseqence3=msg->getSeqNum();
              break;
          case 4 :
              if((int)msg->getSeqNum() < Deseqence4)
              {
                  nbDesquence++;
              }
              Deseqence4=msg->getSeqNum();
              break;
          case 5 :
              if((int)msg->getSeqNum() < Deseqence5)
              {
                  nbDesquence++;
              }
              Deseqence5=msg->getSeqNum();
              break;
          case 6 :
              if((int)msg->getSeqNum() < Deseqence6)
              {
                  nbDesquence++;
              }
              Deseqence6=msg->getSeqNum();
              break;
          default:
              break;
          }
    return true;
}

NetwPkt* PlainFlood::encapsMsg(cPacket *appPkt) {
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
