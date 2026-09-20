"""IDA batch helper used only to finish first-time project database creation."""

import os

import ida_auto
import ida_pro

if os.environ.get("IDA_ASSISTANT_BATCH_WAIT") == "1":
    ida_auto.auto_wait()
ida_pro.qexit(0)
