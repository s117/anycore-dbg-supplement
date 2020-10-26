#!/usr/bin/env python3
from io import BytesIO
from pprint import pformat
from typing import BinaryIO, Any, Callable, List, Dict
from struct import pack, unpack, calcsize
from enum import Enum

try:
    from deepdiff import DeepDiff
except ImportError:
    DeepDiff = None
# define APP_UUID "115fc8b7-8b73-425a-883b-57fc0b10fc25"
# define SIM_ID   "1"

# define COMM_FIFO_BASE_DIR         "/tmp/" APP_UUID
# define COMM_FIFO_FROM_CONTROLLER  COMM_FIFO_BASE_DIR "/" SIM_ID "/c2s"  // c: controller
# define COMM_FIFO_TO_CONTROLLER    COMM_FIFO_BASE_DIR "/" SIM_ID "/s2c"  // s: simulator
# define COMM_FIFO_NODE_MODE        0600

APP_UUID = "115fc8b7-8b73-425a-883b-57fc0b10fc25"
SIM_A_ID = "A"  # Old simulator (Ref)
SIM_B_ID = "B"  # New simulator

COMM_FIFO_BASE_DIR = "/tmp/%s" % APP_UUID
COMM_FIFO_SIM_A_DIR = "%s/%s" % (COMM_FIFO_BASE_DIR, SIM_A_ID)
COMM_FIFO_SIM_B_DIR = "%s/%s" % (COMM_FIFO_BASE_DIR, SIM_B_ID)
COMM_FIFO_NODE_MODE = 0o600

COMM_FIFO_A_S2C_IN = "%s/s2c" % COMM_FIFO_SIM_A_DIR
COMM_FIFO_A_C2S_OUT = "%s/c2s" % COMM_FIFO_SIM_A_DIR
COMM_FIFO_B_S2C_IN = "%s/s2c" % COMM_FIFO_SIM_B_DIR
COMM_FIFO_B_C2S_OUT = "%s/c2s" % COMM_FIFO_SIM_B_DIR

# uint64_t  number of cycle the simulator should skip reporting
SIM_CONF_SKIP_CYCLE = 0
# uint8_t   zero for quiet, non-zero for verbose mode
SIM_CONF_BRIDGE_VERBOSE = False
# cycles that the controller should breakpoint the simulator
SIM_CONF_BREAK_POINT_CYCLE = {
    54746
}


class PrimitiveCppLangType(Enum):
    int8_t = "=b"
    uint8_t = "=B"
    int16_t = "=h"
    uint16_t = "=H"
    int32_t = "=i"
    uint32_t = "=I"
    int64_t = "=q"
    uint64_t = "=Q"
    float = "=f"
    double = "=q"


def recv_c_type(pipe, c_type):
    # type: (BinaryIO, PrimitiveCppLangType) -> Any
    fmt_str = c_type.value
    raw_size = calcsize(fmt_str)
    raw_data = pipe.read(raw_size)
    restored_data = unpack(fmt_str, raw_data)[0]
    return restored_data


def execute_recv(report_format, recv_fn):
    # type: (List[Dict], Callable[[PrimitiveCppLangType],Any]) -> Dict
    report = dict()
    for rpt_field in report_format:
        field_type = rpt_field["type"]  # type: str
        field_name = rpt_field["name"]  # type: str
        field_unpack_handler = rpt_field[
            "unpack_handler"]  # type: Callable[[Callable[[PrimitiveCppLangType],Any]], Dict]

        if field_type.startswith("vector:"):

            recv_vec = []
            recv_vec_len = int(field_type.split(":")[1])
            for i in range(recv_vec_len):
                recv_vec.append(field_unpack_handler(recv_fn))
            report[field_name] = recv_vec
        else:
            report[field_name] = field_unpack_handler(recv_fn)
    return report


def unpack_packet_by_struct(report_format, packet):
    # type: (List[Dict], bytes) -> Dict
    packet_io = BytesIO(packet)

    def real_recv_fn(c_type):
        # type: (PrimitiveCppLangType) -> Any
        data_size = calcsize(c_type.value)
        return unpack(
            c_type.value,
            packet_io.read(data_size)
        )[0]

    report = execute_recv(report_format, real_recv_fn)
    return report


def recv_packet(in_pipe):
    # type: (BinaryIO) -> bytes
    # get the size of packet
    payload_len = in_pipe.read(calcsize(PrimitiveCppLangType.uint32_t.value))
    if len(payload_len) == 0:
        raise ValueError("Broken pipe")
    payload_len = unpack(PrimitiveCppLangType.uint32_t.value, payload_len)[0]
    assert payload_len > 0

    # return the payload of packet
    return in_pipe.read(payload_len)


def recv_report(in_pipe, packet_struct):
    packet_payload = recv_packet(in_pipe)
    return unpack_packet_by_struct(packet_struct, packet_payload)


def send_reply_continue(out_pipe):
    # type: (BinaryIO) -> None
    out_pipe.write('C'.encode('ascii'))
    out_pipe.flush()


def send_reply_debug_break(out_pipe):
    # type: (BinaryIO) -> None
    out_pipe.write('D'.encode('ascii'))
    out_pipe.flush()


def cmp_sim_report(rptA, rptB):
    # type: (Dict, Dict) -> bool
    # this function is wrote in such a strange way because it will be
    # called upon each simulation report is received and it is on the
    # critical path, the current implementation offers better performance
    basic_part_ne = (
            rptA["Basic"]["cycle"] != rptB["Basic"]["cycle"] or
            rptA["Basic"]["sequence"] != rptB["Basic"]["sequence"] or
            rptA["Basic"]["num_insn"] != rptB["Basic"]["num_insn"] or
            rptA["Basic"]["num_insn_split"] != rptB["Basic"]["num_insn_split"]
    )
    if basic_part_ne:
        return False

    fq_part_ne = (
            rptA["FQ"]["head"] != rptB["FQ"]["head"] or
            rptA["FQ"]["tail"] != rptB["FQ"]["tail"] or
            rptA["FQ"]["length"] != rptB["FQ"]["length"]
    )
    if fq_part_ne:
        return False

    iq_part_ne = (
            rptA["IQ"]["length"] != rptB["IQ"]["length"] or
            rptA["IQ"]["fl_head"] != rptB["IQ"]["fl_head"] or
            rptA["IQ"]["fl_tail"] != rptB["IQ"]["fl_tail"] or
            rptA["IQ"]["fl_length"] != rptB["IQ"]["fl_length"]
    )
    if iq_part_ne:
        return False

    ren_part_ne = (
            rptA["REN"]["al_head"] != rptB["REN"]["al_head"] or
            rptA["REN"]["al_tail"] != rptB["REN"]["al_tail"] or
            rptA["REN"]["fl_head"] != rptB["REN"]["fl_head"] or
            rptA["REN"]["fl_tail"] != rptB["REN"]["fl_tail"]
    )
    if ren_part_ne:
        return False

    lsu_part_ne = (
            rptA["LSU"]["lq_head"] != rptB["LSU"]["lq_head"] or
            rptA["LSU"]["lq_tail"] != rptB["LSU"]["lq_tail"] or
            rptA["LSU"]["lq_length"] != rptB["LSU"]["lq_length"] or
            rptA["LSU"]["sq_head"] != rptB["LSU"]["sq_head"] or
            rptA["LSU"]["sq_tail"] != rptB["LSU"]["sq_tail"] or
            rptA["LSU"]["sq_length"] != rptB["LSU"]["sq_length"]
    )
    if lsu_part_ne:
        return False

    def preg_ne(_preg1, _preg2):
        return (
                _preg1["valid"] != _preg2["valid"] or
                _preg1["index"] != _preg2["index"] or
                _preg1["branch_mask"] != _preg2["branch_mask"]
        )

    for pregA, pregB in zip(rptA["Decode"], rptB["Decode"]):
        if preg_ne(pregA, pregB):
            return False
    for pregA, pregB in zip(rptA["Rename2"], rptB["Rename2"]):
        if preg_ne(pregA, pregB):
            return False
    for pregA, pregB in zip(rptA["Dispatch"], rptB["Dispatch"]):
        if preg_ne(pregA, pregB):
            return False

    for laneA, laneB in zip(rptA["Execution_Lanes"], rptB["Execution_Lanes"]):
        rr_wb_part_ne = (
                preg_ne(laneA["rr"], laneB["rr"]) or
                preg_ne(laneA["wb"], laneB["wb"])
        )
        ex_depthA, ex_depthB = laneA["ex_depth"], laneB["ex_depth"]
        if rr_wb_part_ne or ex_depthA != ex_depthB:
            return False
        for laneA_ex_stage, laneB_ex_stage in zip(laneA["ex"], laneB["ex"]):
            if preg_ne(laneA_ex_stage, laneB_ex_stage):
                return False

    return True


class SimABTetheringController:

    def __init__(self, simA_pipe_in, simA_pipe_out, simB_pipe_in, simB_pipe_out):
        import os
        print("Waiting for SimA and SimB process become ready...")
        try:
            os.unlink(simA_pipe_out)
        except FileNotFoundError:
            pass
        try:
            os.unlink(simB_pipe_out)
        except FileNotFoundError:
            pass
        os.mkfifo(simA_pipe_out, COMM_FIFO_NODE_MODE)
        os.mkfifo(simB_pipe_out, COMM_FIFO_NODE_MODE)

        self.m_simA_in_pipe = open(simA_pipe_in, 'rb')
        self.m_simA_in_pipe_path = simA_pipe_in
        self.m_simB_in_pipe = open(simB_pipe_in, 'rb')
        self.m_simB_in_pipe_path = simB_pipe_in

        self.m_simA_out_pipe = open(simA_pipe_out, 'wb')
        self.m_simA_out_pipe_path = simA_pipe_out
        self.m_simB_out_pipe = open(simB_pipe_out, 'wb')
        self.m_simB_out_pipe_path = simB_pipe_out

        print("IPC pipe connected, exchanging parameter...")
        self.current_sim_cycle = SIM_CONF_SKIP_CYCLE

        self.m_sim_fetch_width = 0
        self.m_sim_dispatch_width = 0
        self.m_sim_issue_width = 0
        self.exchange_config_with_simulator()
        self.m_sim_report_fmt = self.compose_sim_report_packet_struct()

    def exchange_config_with_simulator(self):
        def recv_uint32_t(pipe):
            # type: (BinaryIO) -> int
            raw_bytes = pipe.read(calcsize(PrimitiveCppLangType.uint32_t.value))
            value = unpack(PrimitiveCppLangType.uint32_t.value, raw_bytes)
            return value[0]

        def validate_width_param():
            if simA_fetch_width != simB_fetch_width:
                raise RuntimeError(
                    "Two connected simulator cannot be diff because they have different Fetch Width: %d / %d" % (
                        simA_fetch_width, simB_fetch_width
                    )
                )
            if simA_dispatch_width != simB_dispatch_width:
                raise RuntimeError(
                    "Two connected simulator cannot be diff because they have different Dispatch Width: %d / %d" % (
                        simA_dispatch_width, simB_dispatch_width
                    )
                )
            if simA_issue_width != simB_issue_width:
                raise RuntimeError(
                    "Two connected simulator cannot be diff because they have different Issue Width: %d / %d" % (
                        simA_issue_width, simB_issue_width
                    )
                )

        # recv config from connected simulators
        simA_fetch_width = recv_uint32_t(self.m_simA_in_pipe)
        simB_fetch_width = recv_uint32_t(self.m_simB_in_pipe)
        simA_dispatch_width = recv_uint32_t(self.m_simA_in_pipe)
        simB_dispatch_width = recv_uint32_t(self.m_simB_in_pipe)
        simA_issue_width = recv_uint32_t(self.m_simA_in_pipe)
        simB_issue_width = recv_uint32_t(self.m_simB_in_pipe)
        validate_width_param()

        # send config to connected simulators
        self.m_simA_out_pipe.write(pack(PrimitiveCppLangType.uint64_t.value, SIM_CONF_SKIP_CYCLE))
        self.m_simB_out_pipe.write(pack(PrimitiveCppLangType.uint64_t.value, SIM_CONF_SKIP_CYCLE))
        self.m_simA_out_pipe.write(pack(PrimitiveCppLangType.uint8_t.value, SIM_CONF_BRIDGE_VERBOSE))
        self.m_simB_out_pipe.write(pack(PrimitiveCppLangType.uint8_t.value, SIM_CONF_BRIDGE_VERBOSE))
        self.m_simA_out_pipe.flush()
        self.m_simB_out_pipe.flush()

        self.m_sim_fetch_width = simA_fetch_width
        self.m_sim_dispatch_width = simA_dispatch_width
        self.m_sim_issue_width = simA_issue_width

    def compose_sim_report_packet_struct(self):
        def unpack_basic_info(recv_fn):
            # type: (Callable[[PrimitiveCppLangType],Any]) -> Dict
            return {
                "cycle": recv_fn(PrimitiveCppLangType.uint32_t),
                "sequence": recv_fn(PrimitiveCppLangType.uint32_t),
                "num_insn": recv_fn(PrimitiveCppLangType.uint32_t),
                "num_insn_split": recv_fn(PrimitiveCppLangType.uint32_t)
            }

        def unpack_pipeline_reg_elem(recv_fn):
            # type: (Callable[[PrimitiveCppLangType],Any]) -> Dict
            return {
                "valid": recv_fn(PrimitiveCppLangType.uint32_t),
                "index": recv_fn(PrimitiveCppLangType.uint32_t),
                "branch_mask": recv_fn(PrimitiveCppLangType.uint64_t)
            }

        def unpack_Execution_Lanes_elem(recv_fn):
            # type: (Callable[[PrimitiveCppLangType],Any]) -> Dict
            ex_depth = recv_fn(PrimitiveCppLangType.uint32_t)
            ex_stage_reg = []
            for i in range(ex_depth):
                ex_stage_reg.append(unpack_pipeline_reg_elem(recv_fn))
            return {
                "ex_depth": ex_depth,
                "rr": unpack_pipeline_reg_elem(recv_fn),
                "ex": ex_stage_reg,
                "wb": unpack_pipeline_reg_elem(recv_fn)
            }

        def unpack_FQ_info(recv_fn):
            # type: (Callable[[PrimitiveCppLangType],Any]) -> Dict
            return {
                "head": recv_fn(PrimitiveCppLangType.uint32_t),
                "tail": recv_fn(PrimitiveCppLangType.uint32_t),
                "length": recv_fn(PrimitiveCppLangType.uint32_t)
            }

        def unpack_IQ_info(recv_fn):
            # type: (Callable[[PrimitiveCppLangType],Any]) -> Dict
            return {
                "length": recv_fn(PrimitiveCppLangType.uint32_t),
                "fl_head": recv_fn(PrimitiveCppLangType.uint32_t),
                "fl_tail": recv_fn(PrimitiveCppLangType.uint32_t),
                "fl_length": recv_fn(PrimitiveCppLangType.uint32_t)
            }

        def unpack_REN_info(recv_fn):
            # type: (Callable[[PrimitiveCppLangType],Any]) -> Dict
            return {
                "al_head": recv_fn(PrimitiveCppLangType.uint32_t),
                "al_tail": recv_fn(PrimitiveCppLangType.uint32_t),
                "fl_head": recv_fn(PrimitiveCppLangType.uint32_t),
                "fl_tail": recv_fn(PrimitiveCppLangType.uint32_t)
            }

        def unpack_LSU_info(recv_fn):
            # type: (Callable[[PrimitiveCppLangType],Any]) -> Dict
            return {
                "lq_head": recv_fn(PrimitiveCppLangType.uint32_t),
                "lq_tail": recv_fn(PrimitiveCppLangType.uint32_t),
                "lq_length": recv_fn(PrimitiveCppLangType.uint32_t),
                "sq_head": recv_fn(PrimitiveCppLangType.uint32_t),
                "sq_tail": recv_fn(PrimitiveCppLangType.uint32_t),
                "sq_length": recv_fn(PrimitiveCppLangType.uint32_t)
            }

        # https://docs.python.org/3/reference/expressions.html#dictionary-displays
        # If a comma-separated sequence of key/datum pairs is given,
        # they are evaluated from left to right to define the entries of the dictionary
        return [
            {
                "name": "Basic",
                "type": "dict",
                "unpack_handler": unpack_basic_info
            }, {
                "name": "Decode",
                "type": "vector:%d" % self.m_sim_fetch_width,
                "unpack_handler": unpack_pipeline_reg_elem
            }, {
                "name": "Rename2",
                "type": "vector:%d" % self.m_sim_dispatch_width,
                "unpack_handler": unpack_pipeline_reg_elem
            }, {
                "name": "Dispatch",
                "type": "vector:%d" % self.m_sim_dispatch_width,
                "unpack_handler": unpack_pipeline_reg_elem
            }, {
                "name": "Execution_Lanes",
                "type": "vector:%d" % self.m_sim_issue_width,
                "unpack_handler": unpack_Execution_Lanes_elem
            }, {
                "name": "FQ",
                "type": "dict",
                "unpack_handler": unpack_FQ_info
            }, {
                "name": "IQ",
                "type": "dict",
                "unpack_handler": unpack_IQ_info
            }, {
                "name": "REN",
                "type": "dict",
                "unpack_handler": unpack_REN_info
            }, {
                "name": "LSU",
                "type": "dict",
                "unpack_handler": unpack_LSU_info
            }
        ]

    def __del__(self):
        import os

        self.m_simA_out_pipe.close()
        os.unlink(self.m_simA_out_pipe_path)
        self.m_simB_out_pipe.close()
        os.unlink(self.m_simB_out_pipe_path)

        self.m_simA_in_pipe.close()
        self.m_simB_in_pipe.close()

    def run(self):
        # print("Waiting cycle report from SimA and SimB...")
        cycle_report_from_A = recv_report(self.m_simA_in_pipe, self.m_sim_report_fmt)
        cycle_report_from_B = recv_report(self.m_simB_in_pipe, self.m_sim_report_fmt)

        if self.current_sim_cycle != cycle_report_from_A["Basic"]["cycle"]:
            print("Cycle time (%d) mismatch with SimA (%d)" % (
                self.current_sim_cycle, cycle_report_from_A["Basic"]["cycle"]
            ))
        elif self.current_sim_cycle != cycle_report_from_B["Basic"]["cycle"]:
            print("Cycle time (%d) mismatch with SimB (%d)" % (
                self.current_sim_cycle, cycle_report_from_B["Basic"]["cycle"]
            ))

        is_rpt_same = cmp_sim_report(cycle_report_from_A, cycle_report_from_B)

        if is_rpt_same:
            if self.current_sim_cycle in SIM_CONF_BREAK_POINT_CYCLE:
                print("Cycle %d hit the predefined breakpoint cycle." % self.current_sim_cycle)
                send_reply_debug_break(self.m_simA_out_pipe)
                send_reply_debug_break(self.m_simB_out_pipe)
            else:
                # print("Cycle %d cmp passed, continue sim next cycle" % self.current_sim_cycle)
                send_reply_continue(self.m_simA_out_pipe)
                send_reply_continue(self.m_simB_out_pipe)
        else:
            if callable(DeepDiff):
                deep_diff_result = DeepDiff(cycle_report_from_A, cycle_report_from_B)
            else:
                deep_diff_result = "Dependency Deepdiff (https://pypi.org/project/deepdiff/) is not available.\n" \
                                   "  You can obtain it by running 'pip install deepdiff --user'\n"
            print("Cycle %d cmp failed, send breakpoint to AB sim process" % self.current_sim_cycle)
            print("Details: \n\nSimA(old):\n%s\nSimB(new):\n%s\nDiff:\n%s\n\n" % (
                pformat(cycle_report_from_A, indent=2),
                pformat(cycle_report_from_B, indent=2),
                pformat(deep_diff_result, indent=2)
            ))
            send_reply_debug_break(self.m_simA_out_pipe)
            send_reply_debug_break(self.m_simB_out_pipe)

        self.current_sim_cycle += 1


def main():
    import os

    os.makedirs(COMM_FIFO_SIM_A_DIR, 0o700, exist_ok=True)
    os.makedirs(COMM_FIFO_SIM_B_DIR, 0o700, exist_ok=True)

    cp_ipc = SimABTetheringController(
        COMM_FIFO_A_S2C_IN,
        COMM_FIFO_A_C2S_OUT,
        COMM_FIFO_B_S2C_IN,
        COMM_FIFO_B_C2S_OUT
    )
    while True:
        cp_ipc.run()


if __name__ == '__main__':
    main()
