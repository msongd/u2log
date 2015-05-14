package main
import (
	"container/list"
	"io"
)

type U2EventQueue struct {
   List *list.List
}

func NewQueue() *U2EventQueue {
	q := &U2EventQueue{list.New()}
	return q
}

func (q *U2EventQueue) Push(event *SnortEventIpv4AppId) {
	q.List.PushFront(event)
}

func (q *U2EventQueue) AttachExtraData(extraData *Unified2ExtraData) *SnortEventIpv4AppId {
	var foundElement *SnortEventIpv4AppId = nil
	for e:= q.List.Front(); e!= nil; e = e.Next() {
		if extraData.Event_id == e.Value.(*SnortEventIpv4AppId).Event_id {
			foundElement = e.Value.(*SnortEventIpv4AppId)
			if foundElement.ExtraData == nil {
                      foundElement.ExtraData = make([]Unified2ExtraData,1)
                      foundElement.ExtraData[0] = *extraData
             } else {
                      foundElement.ExtraData = append(foundElement.ExtraData, *extraData)
             }
		}
	}
	return foundElement
}

func (q *U2EventQueue) AttachPacket(packet *RawPacket) *SnortEventIpv4AppId {
	var foundElement *SnortEventIpv4AppId = nil
	for e:= q.List.Front(); e!= nil; e = e.Next() {
		if packet.Event_id == e.Value.(*SnortEventIpv4AppId).Event_id {
			foundElement = e.Value.(*SnortEventIpv4AppId)
			if foundElement.ExtraData == nil {
                      foundElement.Packets = make([]RawPacket,1)
                      foundElement.Packets[0] = *packet
             } else {
                      foundElement.Packets = append(foundElement.Packets, *packet)
             }
		}
	}
	return foundElement
}

func (q *U2EventQueue) Dump(finalOut io.Writer) {
    for e:= q.List.Front(); e!= nil; e = e.Next() {
    	DumpJson(e.Value.(*SnortEventIpv4AppId), finalOut)
    }
}
