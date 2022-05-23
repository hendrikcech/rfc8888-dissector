do

    rfc_proto = Proto("rfc8888","RTCP RFC8888")

    rfc_version_f = ProtoField.uint8("rfc8888.version", "Version")
    rfc_padding_f = ProtoField.bool("rfc8888.padding", "Padding")
    rfc_fmt_f = ProtoField.uint8("rfc8888.fmt", "FMT")
    rfc_pt_f = ProtoField.uint8("rfc8888.pt", "Payload type (PT)")
    rfc_length_f = ProtoField.uint16("rfc8888.length", "Length")
    rfc_ssrc_rtcp_f = ProtoField.uint32("rfc8888.ssrc_rtcp", "SSRC of RTCP packet sender")
    -- ...
    rfc_ssrcs_block_rtp_f = ProtoField.none("rfc8888.ssrcs_block_rtp", "SSRCs")
    rfc_ssrc_block_rtp_f = ProtoField.uint32("rfc8888.ssrc_block_rtp", "SSRC")
    rfc_ssrc_rtp_f = ProtoField.bytes("rfc8888.ssrc_rtp", "SSRC")
    rfc_begin_seq_f = ProtoField.uint16("rfc8888.begin_seq", "begin_seq")
    rfc_num_reports_f = ProtoField.uint16("rfc8888.num_reports", "num_reports")

    rfc_pkts_block_f = ProtoField.none("rfc8888.pkts_block", "Packet Feedback")
    rfc_pkt_block_f = ProtoField.string("rfc8888.pkt_block", "Packet")
    rfc_pkt_rcvd_f = ProtoField.bool("rfc8888.pkt_rcvd", "Packet received")
    rfc_pkt_ecn_f = ProtoField.uint8("rfc8888.pkt_ecn", "Packet ECN flag")
    rfc_pkt_arrival_offset_f = ProtoField.float("rfc8888.pkt_arrival_offset", "Packet arrival offset (ms)")

    rfc_report_ts_f = ProtoField.float("rfc8888.report_ts", "Report timestamp")

    rfc_proto.fields = { rfc_version_f, rfc_padding_f, rfc_fmt_f, rfc_pt_f, rfc_length_f, rfc_ssrc_rtcp_f,
                         rfc_ssrcs_block_rtp_f, rfc_ssrc_block_rtp_f, rfc_ssrc_rtp_f, rfc_begin_seq_f, rfc_num_reports_f,
                         rfc_pkts_block_f, rfc_pkt_block_f, rfc_pkt_rcvd_f, rfc_pkt_ecn_f, rfc_pkt_arrival_offset_f,
                         rfc_report_ts_f }

    rfc_not_received_e = ProtoExpert.new("rfc8888.pkt_not_rcvd", "Packet not yet received",
                                expert.group.SEQUENCE, expert.severity.WARN)
    rfc_ofo_report_e = ProtoExpert.new("rfc8888.ofo_report", "Report came in out-of-order",
                                expert.group.SEQUENCE, expert.severity.WARN)
    rfc_ofo_e = ProtoExpert.new("rfc8888.ofo", "Packet received out-of-order",
                                expert.group.SEQUENCE, expert.severity.WARN)
    rfc_proto.experts = { rfc_not_received_e, rfc_ofo_e }

    function rfc_proto.dissector(buffer, pinfo, root)
        if buffer:len() == 0 then return end

        if not pinfo.visited then
            not_rcvd_tbl[pinfo.number] = {}
            ack_range_tbl[pinfo.number] = {}
            ofo_tbl[pinfo.number] = {}
        end

        pinfo.cols.protocol:set("RTCP")

        local rfc_version = bit.rshift(buffer(0,1):uint(), 6)
        local rfc_padding = bit.rshift(bit.band(buffer(0,1):uint(), 0x20), 5)
        local rfc_fmt = bit.band(buffer(0,1):uint(), 0x1f)
        local rfc_pt = buffer(1,1)
        local rfc_length = buffer(2,2)
        local rfc_ssrc_rtcp = buffer(4,4)

        local tree = root:add(rfc_proto)
        tree:add(rfc_version_f, buffer(0,1), rfc_version)
        tree:add(rfc_padding_f, buffer(0,1), rfc_padding)
        tree:add(rfc_fmt_f, buffer(0,1), rfc_fmt)
        tree:add(rfc_pt_f, rfc_pt)
        local length_bytes = (rfc_length:uint()+1) * 4
        tree:add(rfc_length_f, rfc_length, rfc_length:uint(), string.format("Length: %u (%u bytes)", rfc_length:uint(), length_bytes))
        tree:add(rfc_ssrc_rtcp_f, rfc_ssrc_rtcp)

        local report_ts = 0
        if (length_bytes == buffer:len()) then
            local ts_int = buffer(buffer:len()-4, 2):uint()
            local ts_frac = buffer(buffer:len()-2, 2):uint()
            local report_ts = tonumber(ts_int..","..ts_frac)
            -- tree:add(rfc_report_ts_f, buffer(buffer:len()-4, 4), buffer(buffer:len()-4, 4):uint(),
            --          string.format("Report timestamp: %u.%u", ts_int, ts_frac))
            tree:add(rfc_report_ts_f, buffer(buffer:len()-4, 4), report_ts)
        else
            tree:add(rfc_report_ts_f, buffer(buffer:len()-4, 4), -1.0, "The RTCP is not complete and the report timestamp therefore missing")
        end

        -- Decoding SSRC blocks
        c = 8
        local ssrcs_tree = tree:add(rfc_ssrcs_block_rtp_f, buffer(c,buffer:len()-c))
        while (c < buffer:len()) do
            c = decode_ssrc(buffer, pinfo, ssrcs_tree, report_ts, c)
        end
    end

    function decode_ssrc(buffer, pinfo, root, report_ts, c)
        if c + 8 > buffer:len() then return buffer:len() end

        local ssrc_rtp = buffer(c, 4)
        local begin_seq = buffer(c+4, 2)
        local num_reports = buffer(c+6, 2)
        local num_reports_actual = num_reports:uint()+1
        local tree_end = math.min(buffer:len()-c, 8+num_reports_actual*2)

        local tree = root:add(rfc_ssrc_block_rtp_f, buffer(c, tree_end), ssrc_rtp:uint())
        tree:add(rfc_ssrc_rtp_f, ssrc_rtp)
        tree:add(rfc_begin_seq_f, begin_seq)
        tree:add(rfc_num_reports_f, num_reports, num_reports_actual)

        c = c + 8

        local pkts_tree = tree:add(rfc_pkts_block_f, buffer(c, tree_end-8))
        local i_pkt = 0
        local not_rcvd_list = {}
        local not_rcvd_t = {}
        while (num_reports_actual > i_pkt) do
            if c + 2 > buffer:len() then break end
            local pkt_seq = begin_seq:uint()+i_pkt

            local received = bit.band(buffer(c,1):uint(), 0x80)
            local ecn = bit.band(buffer(c,1):uint(), 0x60)
            local arrival_offset = bit.bxor(buffer(c,2):uint(), 0x8000)
            local arrival_time = arrival_offset * (1/1024)

            local pkt_tree_text = ""
            if (received ~= 0) then
                pkt_tree_text = string.format("%d received at %f (offset %f ms)", pkt_seq, report_ts+arrival_time, arrival_time*1000)
            else
                pkt_tree_text = string.format("%d not yet received", pkt_seq)
                table.insert(not_rcvd_list, pkt_seq)
                not_rcvd_t[pkt_seq] = pkt_seq
            end
            local pkt_tree = pkts_tree:add(rfc_pkt_block_f, buffer(c,2), pkt_tree_text)
            pkt_tree:add(rfc_pkt_rcvd_f, buffer(c,1), received)
            pkt_tree:add(rfc_pkt_ecn_f, buffer(c,1), ecn)
            pkt_tree:add(rfc_pkt_arrival_offset_f, buffer(c,2), arrival_time)

            i_pkt = i_pkt + 1
            c = c + 2
        end

        local not_rcvd_str = format_not_rcvd(not_rcvd_list)
        if (#not_rcvd_list > 0) then
            tree:add_proto_expert_info(rfc_not_received_e, not_rcvd_str)
        end

        -- TODO: not a great place to put this
        local info_str = "ACKs "..begin_seq:uint().."-"..(begin_seq:uint()+num_reports_actual-1)..". "..not_rcvd_str
        pinfo.cols.info:set(info_str)


        not_rcvd_tbl[pinfo.number][ssrc_rtp:uint()] = not_rcvd_t
        ack_range_tbl[pinfo.number][ssrc_rtp:uint()] = { begin_seq:uint(), begin_seq:uint()+num_reports_actual }
        detect_ofo(buffer, pinfo, tree, ssrc_rtp:uint(), report_ts)

        return c
    end

    function format_truncated_list(list, max_elements)
        local str = table.concat(list, ",", 1, math.min(max_elements-1, #list))
        if (#list == max_elements) then
            str = str..","..list[max_elements]
        elseif (#list > max_elements) then
            str = str..",...,"..list[#list]
        end
        return str
    end

    function format_not_rcvd(not_rcvd)
        local str = format_truncated_list(not_rcvd, 4)
        if (str ~= "") then
            return ""..#not_rcvd.." missing: "..str
        end
        return str
    end

    prev_report_ts_tbl = {} -- { ssrc: report timestamp }
    prev_report_number_tbl = {} -- { ssrc: pinfo.number }
    not_rcvd_tbl = {} -- { pinfo.number: { ssrc: {not_rcvd: not_rcvd} } }
    ack_range_tbl = {} -- { pinfo.number: { ssrc: [begin_seq, end_seq] } }
    ofo_tbl = {} -- { pinfo.number: { ssrc: [number] } }

    function detect_ofo(buffer, pinfo, root, ssrc, report_ts)
        if not pinfo.visited then
            prev_report_ts = prev_report_ts_tbl[ssrc]
            prev_report_number = prev_report_number_tbl[ssrc]

            if prev_report_ts ~= nil and report_ts < prev_report_ts then
                root:add_proto_expert_info(rfc_ofo_report_e)
                return
            end

            prev_report_ts_tbl[ssrc] = report_ts
            prev_report_number_tbl[ssrc] = pinfo.number

            if prev_report_ts == nil or prev_report_number == nil then
                -- First report of this ssrc
                ofo_tbl[pinfo.number][ssrc] = {}
                return
            end

            local ack_range_prev = ack_range_tbl[prev_report_number][ssrc]
            local ack_range = ack_range_tbl[pinfo.number][ssrc]
            local not_rcvd_prev = not_rcvd_tbl[prev_report_number][ssrc]
            local not_rcvd = not_rcvd_tbl[pinfo.number][ssrc]
            local ofo = {}
            local i_pkt = ack_range[1]
            while (i_pkt <= ack_range[2]) do
                if (not_rcvd_prev[i_pkt] ~= nil and not_rcvd[i_pkt] == nil) then
                    table.insert(ofo, i_pkt)
                end
                i_pkt = i_pkt + 1
            end
            ofo_tbl[pinfo.number][ssrc] = ofo
            -- print("Comparing "..ack_range[1].."-"..ack_range[2])
            -- if #not_rcvd_prev > 0 then
            --     print("prev: "..format_truncated_list(not_rcvd_prev, 10))
            --     print("curr: "..format_truncated_list(not_rcvd, 10))
            -- end
        end

        local ofo = ofo_tbl[pinfo.number][ssrc]
        if #ofo_tbl[pinfo.number][ssrc] > 0 then
            local ofo_str = "Received ofo: "..format_truncated_list(ofo, 4)
            root:add_proto_expert_info(rfc_ofo_e, ofo_str)
        end
    end
end

-- test with:
-- tshark -O RFC8888 -V -r pi_focus.pcap "udp.srcport==6006"
