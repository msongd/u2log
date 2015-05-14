package main
import (
	"container/list"
	"io"
	//"log"
)

type U2EventQueue struct {
   List *list.List
   MaxLen int
   PopCallback PopCallback
}

type PopCallback func(*SnortEventIpv4AppId)

func NewQueue(maxLen int, pC PopCallback) *U2EventQueue {
	q := &U2EventQueue{list.New(), maxLen, pC}
	return q
}

func (q *U2EventQueue) Push(event *SnortEventIpv4AppId) {
	currentLen :=q.List.Len()
	//fmt.Println("[INFO] curLen:", currentLen, ",maxLen:",q.MaxLen)
	if currentLen == q.MaxLen {
		lastElem := q.List.Back()
		q.List.Remove(lastElem)
		q.PopCallback(lastElem.Value.(*SnortEventIpv4AppId))
		q.List.PushFront(event)
	} else {
		q.List.PushFront(event)
		//log.Println("[INFO] Pustfront:", event.Event_id)
	}
}

func (q *U2EventQueue) AttachExtraData(extraData *Unified2ExtraData) *SnortEventIpv4AppId {
	var foundElement *SnortEventIpv4AppId = nil
	//eventIdArray := make([]uint32, q.MaxLen)
	//i:=0
	for e:= q.List.Front(); e!= nil; e = e.Next() {
		//eventIdArray[i] = e.Value.(*SnortEventIpv4AppId).Event_id
		//i=i+1
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
	/*
	if foundElement == nil {
		log.Println("[INFO] Search for:", extraData.Event_id,",but has:",eventIdArray) 
	}
	*/
	return foundElement
}

func (q *U2EventQueue) AttachPacket(packet *RawPacket) *SnortEventIpv4AppId {
	var foundElement *SnortEventIpv4AppId = nil
	//eventIdArray := make([]uint32, q.MaxLen)
	//i:=0
	for e:= q.List.Front(); e!= nil; e = e.Next() {
		//eventIdArray[i] = e.Value.(*SnortEventIpv4AppId).Event_id
		//i=i+1
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
	/*
	if foundElement == nil {
		log.Println("[INFO] Search for:", packet.Event_id,",but has:",eventIdArray) 
	}
	*/
	return foundElement
}

func (q *U2EventQueue) Dump(finalOut io.Writer) {
    for e:= q.List.Back(); e!= nil; e = e.Prev() {
    	DumpJson(e.Value.(*SnortEventIpv4AppId), finalOut)
    }
}
