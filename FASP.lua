FASP = Proto("FASP",  "Fast And Secure Protocol")

trans_id = ProtoField.uint8("FASP.trans_id", "Transfer ID", base.DEC)
opcode = ProtoField.uint8("fasp.opcode", "opCode", base.DEC)
seq_num = ProtoField.uint32("fasp.seq", "Sequence Num", base.DEC)
ip_len = ProtoField.uint32("fasp.iplen", "IP Length", base.DEC)
timestamp = ProtoField.uint32("fasp.timestamp", "Timestamp", base.DEC)
recv_len = ProtoField.uint32("fasp.recvlen", "Recv Length", base.DEC)
uuid = ProtoField.string("fasp.uuid", "UUID", base.ASCII)

FASP.fields = { trans_id, opcode, seq_num, ip_len, timestamp, recv_len, uuid }

function get_opcode_name(opcode)
  local opcode_name = "Unknown"

  if opcode == 0x11 then opcode_name = "TRANS END"
  elseif opcode == 0x12 then opcode_name = "RETRANS REQ"
  elseif opcode == 0x13 then opcode_name = "ADJUST SPEED"
  elseif opcode == 0x19 then opcode_name = "RETRANS"
  elseif opcode == 0x1a then opcode_name = "RETRANS 2"
  elseif opcode == 0x20 then opcode_name = "Unknown"
  elseif opcode == 0x21 then opcode_name = "TRANS DATA"
  end

  return opcode_name
end

function FASP.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = FASP.name

  local subtree = tree:add(FASP, buffer(), "FASP")

  subtree:add(trans_id, buffer(0, 1))

  local _opcode = buffer(1, 1):uint()
  local opcode_name = get_opcode_name(_opcode)
  subtree:add(opcode, buffer(1, 1)):append_text(" (" .. opcode_name .. ")")

  if _opcode == 0x13 then
    subtree:add(seq_num, buffer(4, 4))
    subtree:add(seq_num, buffer(12, 4))
  elseif _opcode == 0x20 then
    subtree:add(seq_num, buffer(4, 4))
    subtree:add(uuid, buffer(8, 36))
  elseif _opcode == 0x21 then
    subtree:add(seq_num, buffer(4, 4))
    subtree:add(ip_len, buffer(8, 4))
    subtree:add(timestamp, buffer(12, 4))
    subtree:add(recv_len, buffer(16, 4))
    subtree:add(uuid, buffer(20, 36))
  end
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(33001, FASP)