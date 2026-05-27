`uvm_analysis_imp_decl(_ap_1)
`uvm_analysis_imp_decl(_ap_2)

class eth_scb extends uvm_scoreboard;
  `uvm_component_utils(eth_scb);
  
  uvm_analysis_imp_ap_1#(eth_seq_item, eth_scb) ai_1[`NO_OF_AGENTS];    
  uvm_analysis_imp_ap_2#(eth_seq_item, eth_scb) ai_2[`NO_OF_AGENTS];  
  

  eth_seq_item tx_tr;
  eth_seq_item rx_tr;
  
 // eth_seq_item tx_aa[int][int];//agent name , transaction number
//  eth_seq_item rx_aa[int][int];
  
  // TX ARRAY
// [source_agent][destination_agent][transaction_number]
eth_seq_item tx_aa[int][int][int];

// RX ARRAY
// [source_agent][destination_agent][transaction_number]
eth_seq_item rx_aa[int][int][int];
  int rx_count[int][int]; // [src][dst]
  int tx_count[int][int];
  
int exp_err_pkt_no;
  int compare_count;
int pass_count;
int fail_count;
int drop_count;
 bit exp_ext_en;
  
  
  function new(string name = "eth_scb", uvm_component parent = null);
    super.new(name,parent);
   
    foreach(ai_1[i])
      ai_1[i]=new($sformatf ("ai_1[%0d]",i),this);
         
    foreach(ai_2[i])
      ai_2[i]=new($sformatf ("ai_2[%0d]",i),this);
    
    
  endfunction   
  
  function void build_phase(uvm_phase phase);
    super.build_phase(phase); 
   
  endfunction  
  
function void write_ap_1(eth_seq_item tx_tr);

  int src_id;
  int dst_id;

  src_id = source_address(tx_tr);
  dst_id = destination_address(tx_tr);

  //-----------------------------------------
  // Invalid destination address
  // Store in special bucket
  //-----------------------------------------
  if(dst_id == -1) begin

    dst_id = `NO_OF_AGENTS;

    `uvm_info("SCB_INVALID_DA_STORE",
      $sformatf(
        "Invalid DA packet stored : DA=%012h",
        tx_tr.da),
      UVM_LOW)

  end

  //-----------------------------------------
  // Store TX transaction
  //-----------------------------------------
  tx_count[src_id][dst_id]++;
  $display("-------------------2222222222222222 %0d",tx_count[src_id][dst_id]);

  tx_aa[src_id][dst_id][tx_count[src_id][dst_id]] = tx_tr;

 `uvm_info("SCB_TX",
  $sformatf(
    "Stored TX Packet : TX_AGENT[%0d] --> RX_AGENT[%0d] | TX_NO=%0d | DA=%012h | SA=%012h",
    src_id,
    dst_id,
    tx_count[src_id][dst_id],
    tx_tr.da,
    tx_tr.sa),
  UVM_LOW)

endfunction
  
 function bit is_error_pkt(eth_seq_item tr);

  // TX_ER
  if(tr.err_b)
    return 1;

return 0;

endfunction
 
  
 function void write_ap_2(eth_seq_item rx_tr);

  int src_id;
  int dst_id;
  int txn_no;

  // Decode source and destination from RX packet
  src_id = source_address(rx_tr);       // from SA
  dst_id = destination_address(rx_tr);  // from DA

  if(src_id == -1 || dst_id == -1)
    return;

  // Use rx_count as transaction number
  txn_no = rx_tr.rx_count;

  if((!tx_aa.exists(src_id) || !tx_aa[src_id].exists(dst_id) || !tx_aa[src_id][dst_id].exists(txn_no))) begin

    `uvm_error("SCB_EXTRA_RX",
      $sformatf("RX received but matching TX not found: RX[%0d][%0d][%0d]",
                src_id, dst_id, txn_no))
		//rx_tr.print();
    return;
  end

  // Check corresponding TX packet
  if(is_error_pkt(tx_aa[src_id][dst_id][txn_no])) begin

    // Bad packet reached RX, store it in rx_aa for debug
    rx_aa[src_id][dst_id][txn_no] = rx_tr;
  `uvm_error("SCB_BAD_PKT_RX",
      $sformatf(
        "FAIL: Bad Packet Reached RX | TX_AGENT[%0d] --> RX_AGENT[%0d] | TX_NO=%0d | RX_NO=%0d",
        src_id,
        dst_id,
        txn_no,
        rx_tr.rx_count))

    return;
  end

  // Good packet: compare directly
  compare_packet(
    src_id,
    dst_id,
    txn_no,
    rx_tr.rx_count,
    tx_aa[src_id][dst_id][txn_no],
    rx_tr
  );

  // Delete compared TX
  tx_aa[src_id][dst_id].delete(txn_no);

endfunction
  
 function void check_phase(uvm_phase phase);

  super.check_phase(phase);

  foreach(tx_aa[src_id]) begin
    foreach(tx_aa[src_id][dst_id]) begin
      foreach(tx_aa[src_id][dst_id][txn_no]) begin

        //-----------------------------------------
        // BAD PACKET
        //-----------------------------------------
        if(is_error_pkt(tx_aa[src_id][dst_id][txn_no])) begin
 `uvm_info("SCB_BAD_PKT_PASS",
            $sformatf({
              "\n========================================================",
              "\nPASS : Bad Packet Correctly Dropped",
              "\n--------------------------------------------------------",
              "\nTX_AGENT        : %0d",
              "\nEXPECTED_RX     : %0d",
              "\nTX_TRANSACTION  : %0d",
              "\nDA              : %012h",
              "\nSA              : %012h",
              "\n========================================================"
            },
            src_id,
            dst_id,
            txn_no,
            tx_aa[src_id][dst_id][txn_no].da,
            tx_aa[src_id][dst_id][txn_no].sa),
            UVM_LOW)

            // delete only bad packet
          tx_aa[src_id][dst_id].delete(txn_no);


        end

        //-----------------------------------------
        // GOOD PACKET
        //-----------------------------------------
        else begin

         `uvm_error("SCB_MISSING_RX",
            $sformatf({
              "\n========================================================",
              "\nFAIL : Good Packet Missing At RX",
              "\n--------------------------------------------------------",
              "\nTX_AGENT        : %0d",
              "\nEXPECTED_RX     : %0d",
              "\nTX_TRANSACTION  : %0d",
              "\nDA              : %012h",
              "\nSA              : %012h",
              "\n========================================================"
            },
            src_id,
            dst_id,
            txn_no,
            tx_aa[src_id][dst_id][txn_no].da,
                      tx_aa[src_id][dst_id][txn_no].sa))// keep the good packet for debugging purpose

        end


      end
    end
  end

endfunction
 
//   //expected data received from monitor
//   function void write_ap_1(eth_seq_item tx_tr);
    
   

//   int src_id;
//   int dst_id;

    
//   src_id = source_address(tx_tr);
//   dst_id = destination_address(tx_tr);

    
    
//   if (src_id == -1)
//     return;

//   // Store even if dst_id == -1
//   tx_aa[src_id][count[src_id]] = tx_tr;
    

//   `uvm_info("SCB_TX",
//     $sformatf("Stored TX: src=%0d dst=%0d tx_aa[%0d][%0d]",
//               src_id, dst_id, src_id, count[src_id]),
//     UVM_LOW)
//      `uvm_info("SCB_TX_DEBUG",
//   $sformatf("TX received: src=%0d dst=%0d err_b=%0d",
//             src_id, dst_id, tx_tr.err_b),
//   UVM_LOW)
  
//     `uvm_info("TX_TR_DEBUG",
//           $sformatf("\n%s", tx_tr.sprint()),
//           UVM_DEBUG)
//      tx_tr.print();

//   count[src_id]++;

//  // sb_compare();

// endfunction
  
  
//   function void write_ap_2(eth_seq_item rx_tr);

//   int rx_id;
    
//     rx_id = destination_address(rx_tr); // decode from DA


//  // rx_id = rx_tr.agent_id; // RX monitor id

//   rx_aa[rx_id][rx_tr.rx_count] = rx_tr;

//   `uvm_info("SCB_RX",
//     $sformatf("Stored RX: rx_id=%0d rx_count=%0d",
//               rx_id, rx_tr.rx_count),
//     UVM_LOW)
//     rx_tr.print();

// endfunction
  
  
//   function void check_phase(uvm_phase phase);
//   super.check_phase(phase);

//   `uvm_info("SCB_CHECK", "All transactions stored. Starting final compare", UVM_LOW)

//   sb_compare();

// endfunction
  
// function void sb_compare();

//   int dst_id;

//   foreach(tx_aa[src_id]) begin

//     foreach(tx_aa[src_id][tx_no]) begin

//       dst_id = destination_address(tx_aa[src_id][tx_no]);

//       if(dst_id == -1) begin
//         `uvm_info("SCB_INVALID_DA",
//           $sformatf("Invalid DA expected drop. TX_AGENT=%0d TX_NO=%0d",
//                     src_id, tx_no),
//           UVM_LOW)
//         drop_count++;
//         continue;
//       end
//       /*
//       //carrier extension
//       if(exp_ext_en && tx_aa[src_id][tx_no].exp_mode == 0 &&
//    tx_aa[src_id][tx_no].ether_type < 486) begin

//   if(tx_aa[src_id][tx_no].ext_en) begin
//     `uvm_info("SCB_EXT_PASS",
//       $sformatf("PASS: Carrier extension detected. TX_AGENT=%0d TX_NO=%0d EXT_BYTES=%0d",
//                 src_id, tx_no, tx_aa[src_id][tx_no].ext_byte_count),
//       UVM_LOW)
//   end
//   else begin
//     fail_count++;

//     `uvm_error("SCB_EXT_FAIL",
//       $sformatf("FAIL: Carrier extension expected but not detected. TX_AGENT=%0d TX_NO=%0d",
//                 src_id, tx_no))
//   end

// end
// */
//       //
//       //---------------------------------------
//       // BAD PACKET CASE
//       //---------------------------------------
//       if(tx_aa[src_id][tx_no].ether_len_mismatch== 1 || tx_aa[src_id][tx_no].corrupt_fcs_en == 1 || tx_aa[src_id][tx_no].preamble_err == 1 || tx_no == exp_err_pkt_no || tx_aa[src_id][tx_no].err_b == 1  ) begin

//         if(rx_aa.exists(dst_id) &&
//            rx_aa[dst_id].exists(tx_no)) begin

//           `uvm_error("SCB_ERR_PKT",
//             $sformatf("FAIL: Bad packet reached RX. TX_AGENT=%0d TX_NO=%0d RX_AGENT=%0d RX_NO=%0d",
//                       src_id, tx_no, dst_id, tx_no))

//         end
//         else begin
          
//           drop_count++;
// `uvm_info("SCB_ERR_PKT_PASS",
//   $sformatf(
//     "Bad packet correctly dropped: TX_AGENT[%0d] -> RX_AGENT[%0d], DROPPED_TX_PACKET_NO = %0d",
//     src_id,
//     dst_id,
//     tx_no),
//   UVM_LOW)

//         end

//         continue;
//       end

//       //---------------------------------------
//       // GOOD PACKET CASE
//       //---------------------------------------
//       if(rx_aa.exists(dst_id) &&
//          rx_aa[dst_id].exists(tx_no)) begin

//         `uvm_info("SCB_COMPARE",
//           $sformatf("Comparing TX[%0d][%0d] -> RX[%0d][%0d]",
//                     src_id, tx_no, dst_id, tx_no),
//           UVM_LOW)

//         compare_count++;
        
// compare_packet(
//   src_id,
//   dst_id,
//   tx_no,
//   rx_aa[dst_id][tx_no].rx_count,
//   tx_aa[src_id][tx_no],
//   rx_aa[dst_id][tx_no]
// );
//       end
//       else begin
//             fail_count++;
//         `uvm_error("SCB_MISSING_RX",
//           $sformatf("FAIL: Good TX packet missing at RX. TX_AGENT=%0d TX_NO=%0d RX_AGENT=%0d",
//                     src_id, tx_no, dst_id))

//       end

//     end
//   end

// endfunction
  
//   function void report_phase(uvm_phase phase);
//   super.report_phase(phase);

//   `uvm_info("SCB_SUMMARY",
//     $sformatf({
//       "\n================ SCOREBOARD SUMMARY ================",
//       "\nTotal comparisons : %0d",
//       "\nPass comparisons  : %0d",
//       "\nFail comparisons  : %0d",
//       "\nDropped packets   : %0d",
//       "\n===================================================="
//     },
//     compare_count,
//     pass_count,
//     fail_count,
//     drop_count),
//     UVM_LOW)

// endfunction


function void compare_packet(
  int tx_id,
  int rx_id,
  int tx_no,
  int rx_no,
  eth_seq_item tx_tr,
  eth_seq_item rx_tr);
  bit pass = 1;
  
  // ---------------------------
  // Destination Address compare
//   // ---------------------------
//   foreach (tx_tr.da[i]) begin
//     if (tx_tr.da[i] !== rx_tr.da[i]) begin
//       `uvm_error("SCB",
//         $sformatf("DA mismatch byte[%0d]: TX=%0h RX=%0h",
//                   i, tx_tr.da[i], rx_tr.da[i]))
//       pass = 0;
//     end
//   end

//   // ---------------------------
//   // Source Address compare
//   // ---------------------------
//   foreach (tx_tr.sa[i]) begin
//     if (tx_tr.sa[i] !== rx_tr.sa[i]) begin
//       `uvm_error("SCB",
//         $sformatf("SA mismatch byte[%0d]: TX=%0h RX=%0h",
//                   i, tx_tr.sa[i], rx_tr.sa[i]))
//       pass = 0;
//     end
//   end
if(tx_tr.da !== rx_tr.da) begin
  `uvm_error("SCB_DA",
    $sformatf("DA mismatch: TX=%012h RX=%012h",
              tx_tr.da, rx_tr.da))
  pass = 0;
end

if(tx_tr.sa !== rx_tr.sa) begin
  `uvm_error("SCB_SA",
    $sformatf("SA mismatch: TX=%012h RX=%012h",
              tx_tr.sa, rx_tr.sa))
  pass = 0;
end
  // ---------------------------
  // EtherType compare
  // ---------------------------
  if (tx_tr.ether_type !== rx_tr.ether_type) begin
    `uvm_error("SCB",
      $sformatf("EtherType mismatch: TX=%0h RX=%0h",
                tx_tr.ether_type, rx_tr.ether_type))
    pass = 0;
  end

  // ---------------------------
  // Payload size compare
  // ---------------------------
  if (tx_tr.payload.size() != rx_tr.payload.size()) begin
    `uvm_error("SCB",
      $sformatf("Payload size mismatch: TX=%0d RX=%0d",
                tx_tr.payload.size(), rx_tr.payload.size()))
    pass = 0;
  end
  else begin
    foreach (tx_tr.payload[i]) begin
      if (tx_tr.payload[i] !== rx_tr.payload[i]) begin
        `uvm_error("SCB",
          $sformatf("Payload mismatch byte[%0d]: TX=%0h RX=%0h",
                    i, tx_tr.payload[i], rx_tr.payload[i]))
        pass = 0;
      end
    end
  end
// ---------------------------
// VLAN compare
// ---------------------------
if (tx_tr.vlan_en !== rx_tr.vlan_en) begin
  `uvm_error("SCB_VLAN",
    $sformatf("VLAN_EN mismatch: TX=%0b RX=%0b",
              tx_tr.vlan_en, rx_tr.vlan_en))
  pass = 0;
end

if (tx_tr.vlan_en) begin

  if (rx_tr.TPID !== 16'h8100) begin
    `uvm_error("SCB_TPID",
      $sformatf("TPID mismatch: Expected=8100 RX=%04h",
                rx_tr.TPID))
    pass = 0;
  end

  if (tx_tr.TPID !== rx_tr.TPID) begin
    `uvm_error("SCB_TPID",
      $sformatf("TPID mismatch: TX=%04h RX=%04h",
                tx_tr.TPID, rx_tr.TPID))
    pass = 0;
  end

  if (tx_tr.PCP !== rx_tr.PCP) begin
    `uvm_error("SCB_PCP",
      $sformatf("PCP mismatch: TX=%0d RX=%0d",
                tx_tr.PCP, rx_tr.PCP))
    pass = 0;
  end

  if (tx_tr.DEI !== rx_tr.DEI) begin
    `uvm_error("SCB_DEI",
      $sformatf("DEI mismatch: TX=%0b RX=%0b",
                tx_tr.DEI, rx_tr.DEI))
    pass = 0;
  end

  if (tx_tr.VID !== rx_tr.VID) begin
    `uvm_error("SCB_VID",
      $sformatf("VID mismatch: TX=%0d RX=%0d",
                tx_tr.VID, rx_tr.VID))
    pass = 0;
  end
end
  // ---------------------------
  // Final result
  // ---------------------------
 if (pass) begin

     pass_count++;
   
   `uvm_info("SCB_TRANS_NUM",
  $sformatf({
    "\nTX_TRANSACTION_NO = %0d",
    "\nRX_TRANSACTION_NO = %0d"
  },
  tx_no,
  rx_no),
  UVM_LOW)
 `uvm_info("SCB_COMPARE",
    $sformatf({
      "\n==============================================================================",
      "\n%-18s : %-18s | %-18s : %-18s",
      "\n==============================================================================",
      "\n%-18s : %-18d | %-18s : %-18d",
      "\n%-18s : %012h       | %-18s : %012h",
      "\n%-18s : %012h       | %-18s : %012h",
      "\n%-18s : %04h             | %-18s : %04h",
      "\n%-18s : %-18h | %-18s : %-18h",
      "\n%-18s : %08h           | %-18s : %08h",
      "\n%-18s : %-18b | %-18s : %-18b",
      "\n=============================================================================="
    },

    "EXPECTED (TX)", "", "ACTUAL (RX)", "",

    "TX_AGENT", tx_id,
    "RX_AGENT", rx_id,

    "DA", tx_tr.da,
    "DA", rx_tr.da,

    "SA", tx_tr.sa,
    "SA", rx_tr.sa,

    "ETHER_TYPE", tx_tr.ether_type,
    "ETHER_TYPE", rx_tr.ether_type,

    "PAYLOAD_SIZE", tx_tr.payload.size(),
    "PAYLOAD_SIZE", rx_tr.payload.size(),

    "CRC", tx_tr.crc,
    "CRC", rx_tr.crc,

    "ERR_B", tx_tr.err_b,
    "ERR_B", rx_tr.err_b
    ),UVM_LOW)   
    
   if(tx_tr.vlan_en)
`uvm_info("SCB_VLAN_INFO",
  $sformatf({
    "\n================ VLAN INFO ================",
    "\nTX_VLAN_EN : %0b   | RX_VLAN_EN : %0b",
    "\nTX_TPID    : %04h | RX_TPID    : %04h",
    "\nTX_PCP     : %0d    | RX_PCP     : %0d",
    "\nTX_DEI     : %0b    | RX_DEI     : %0b",
    "\nTX_VID     : %0d | RX_VID     : %0d",
    "\n==========================================="
  },

  tx_tr.vlan_en, rx_tr.vlan_en,
  tx_tr.TPID,    rx_tr.TPID,
  tx_tr.PCP,     rx_tr.PCP,
  tx_tr.DEI,     rx_tr.DEI,
  tx_tr.VID,     rx_tr.VID
  ),
  UVM_LOW)
     `uvm_info("SCB_RX_COUNT",
  $sformatf("RX packet count received in SB = %0d",
            rx_tr.rx_count),
  UVM_LOW)
  end
  else begin
     fail_count++;
    
    `uvm_error("SCB_FAIL",
      $sformatf("Packet mismatch: TX agent[%0d] -> RX agent[%0d]",
                tx_id, rx_id))
  end

endfunction

  
  //converts mac address into agent number
//    function int source_address(eth_seq_item tx_tr);

//   bit [7:0] last_byte;

//      last_byte = tx_tr.sa[7:0];
//  if (last_byte >= 8'h10 && last_byte < (8'h10 + `NO_OF_AGENTS))
   
 
//   return last_byte - 8'h10;
//   else begin
//     `uvm_error("SB_Source_address", $sformatf("Invalid SA = %0p, last_byte = %0h",
//                                tx_tr.sa, last_byte))
//     return -1;
//   end
    
//   endfunction
    function int source_address(eth_seq_item tx_tr);

  for(int i = 0; i < `NO_OF_AGENTS; i++) begin

    if(tx_tr.sa == tx_tr.mac_addr[i])
      return i;

  end

  `uvm_error("SB_INVALID_SA",
    $sformatf(
      "Invalid Source Address Detected : SA=%012h",
      tx_tr.sa))

  return -1;

endfunction
      //calculating destination address
//   function int destination_address(eth_seq_item tx_tr);

//   bit [7:0] last_byte;

//     last_byte = tx_tr.da[7:0];

//   if (last_byte >= 8'h10 && last_byte < (8'h10 + `NO_OF_AGENTS))
    
 
    
//     return (last_byte - 8'h10);
//   else begin
 
//     `uvm_info("SB_destination_address",
//   $sformatf("Invalid DA: RX_MON expected to be dropped: DA=%h last_byte=%0h",
//             tx_tr.da, last_byte),
//   UVM_LOW)
//     return -1;
//   end

// endfunction
   function int destination_address(eth_seq_item tx_tr);

  for(int i = 0; i < `NO_OF_AGENTS; i++) begin

    if(tx_tr.da == tx_tr.mac_addr[i])
      return i;

  end

  `uvm_info("SB_INVALID_DA",
    $sformatf(
      "Invalid Destination Address Detected : DA=%012h",
      tx_tr.da),
    UVM_LOW)

  return -1;

endfunction
   
  

  
  /*

   function void compare(int i,eth_seq_item tx_tr,eth_seq_item rx_tr);
     `uvm_info("SCORBOARD",$sformatf("Base write() agent = %0d, txd = %p, rxd = %p",i,tx_tr.sa, rx_tr.sa), UVM_LOW)
     
  endfunction 
  */
  
endclass
