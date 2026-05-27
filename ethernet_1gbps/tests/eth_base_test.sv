class eth_test extends uvm_test;
  `uvm_component_utils(eth_test);
  
  eth_env env_h;
  virtual_seq v_seq;
  int no_of_pkts = 100;

  
  function new(string name = "eth_test", uvm_component parent = null);
    super.new(name,parent);
    
  endfunction
  
  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    env_h = eth_env::type_id::create("env_h",this);
  endfunction
  
  function void end_of_elaboration_phase(uvm_phase phase);
    super.end_of_elaboration_phase(phase);
    uvm_top.print_topology();
  endfunction
  

endclass

class gmii_eth_normal_frame_test extends eth_test;
  `uvm_component_utils(gmii_eth_normal_frame_test)
  
  function new (string name = "gmii_eth_normal_frame_test", uvm_component parent = null);
    super.new(name, parent);
  endfunction
  
  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction  

    
  task run_phase(uvm_phase phase);
    virtual_seq vseq;
    
    phase.raise_objection(this); 
    repeat(this.no_of_pkts) begin
      vseq = virtual_seq::type_id::create("vseq");
      vseq.mode = 1;
      vseq.payload_rand_en = 1;
      vseq.padding_en = 1;
      vseq.start(env_h.vseqr_h);  
    end
    #100;
    phase.drop_objection(this);
  endtask  

endclass


class gmii_eth_max_size_frame_test extends eth_test;
  `uvm_component_utils(gmii_eth_max_size_frame_test)
  
  function new (string name = "gmii_eth_max_size_frame_test", uvm_component parent = null);
    super.new(name, parent);
  endfunction
  
  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction  

    
  task run_phase(uvm_phase phase);
    virtual_seq vseq;
    
    phase.raise_objection(this);
    repeat(this.no_of_pkts) begin
      vseq = virtual_seq::type_id::create("vseq");
      vseq.mode = 1;
      vseq.ether_type = 1500;
      vseq.padding_en =1;
      vseq.start(env_h.vseqr_h);
    end
    #100;
    phase.drop_objection(this);
  endtask  

endclass


class gmii_eth_min_size_frame_test extends eth_test;
  `uvm_component_utils(gmii_eth_min_size_frame_test)
  
  function new (string name = "gmii_eth_min_size_frame_test", uvm_component parent = null);
    super.new(name, parent);
  endfunction
  
  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction  

    
  task run_phase(uvm_phase phase);
    virtual_seq vseq;
    
    phase.raise_objection(this); 

    repeat(this.no_of_pkts) begin
      vseq = virtual_seq::type_id::create("vseq");
      vseq.mode = 1;  
      vseq.ether_type = 40;
      vseq.padding_en =1;
      vseq.start(env_h.vseqr_h);    
    end
    #100;
    phase.drop_objection(this);

  endtask  

endclass


class gmii_eth_error_detection_test extends eth_test;
  `uvm_component_utils(gmii_eth_error_detection_test)
  
  function new (string name = "gmii_eth_error_detection_test", uvm_component parent = null);
    super.new(name,parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction    
  
  task run_phase(uvm_phase phase);
    virtual_seq vseq;
    
    phase.raise_objection(this); 
      vseq = virtual_seq::type_id::create("vseq");
    
      // same info to scoreboard
      vseq.error_pkt_no = $urandom_range(1, no_of_pkts);
      env_h.scb_h.exp_err_pkt_no = vseq.error_pkt_no;      
    repeat(this.no_of_pkts) begin
      vseq.mode = 1;
      vseq.payload_rand_en = 1;
      vseq.err_b = 1;
      vseq.err_offset = 50;  
      vseq.padding_en =1;
      vseq.start(env_h.vseqr_h); 
    end
    #100;
    phase.drop_objection(this);
  endtask    
  
endclass


class gmii_eth_vlan_tag_frame_test extends eth_test;
  `uvm_component_utils(gmii_eth_vlan_tag_frame_test)
  
  function new (string name = "gmii_eth_vlan_tag_frame_test", uvm_component parent = null);
    super.new(name,parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction    
  
  task run_phase(uvm_phase phase);
    virtual_seq vseq;
    
    phase.raise_objection(this);  
    repeat(this.no_of_pkts) begin
      vseq = virtual_seq::type_id::create("vseq");
      vseq.mode = 1;
      vseq.vlan_en = 1;
      vseq.payload_rand_en = 1;
      vseq.TPID = 16'h8100;  
      vseq.padding_en =1;
      vseq.start(env_h.vseqr_h);    
    end
    phase.drop_objection(this);
  endtask    
  
endclass



class gmii_eth_preamble_corruption_test extends eth_test;
  `uvm_component_utils(gmii_eth_preamble_corruption_test)
  
  function new (string name = "gmii_eth_preamble_corruption_test", uvm_component parent = null);
    super.new(name,parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction    
  
  task run_phase(uvm_phase phase);
    virtual_seq vseq;
    
    phase.raise_objection(this);  
      
    repeat(this.no_of_pkts) begin
      vseq = virtual_seq::type_id::create("vseq");  
      vseq.mode = 1;
      vseq.payload_rand_en = 1;
      vseq.corrupt_preamble_en = 1;   
      vseq.set_corpt_pkt = 3;
      vseq.padding_en =1;
      vseq.start(env_h.vseqr_h);    
    end
    #100;
    phase.drop_objection(this);
  endtask    
endclass


class gmii_eth_frame_with_ext_bit_test extends eth_test;
  `uvm_component_utils(gmii_eth_frame_with_ext_bit_test)
  
  function new (string name = "gmii_eth_frame_with_ext_bit_test", uvm_component parent = null);
    super.new(name,parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction    
  
  task run_phase(uvm_phase phase);
    virtual_seq vseq;
    
    phase.raise_objection(this);  
    repeat(this.no_of_pkts) begin
      vseq = virtual_seq::type_id::create("vseq");
      vseq.mode = 0; //Carrier extension only for half-duplex
      vseq.payload_rand_en = 0;
      vseq.carr_ext_en = 1;
      vseq.padding_en =1;
      vseq.start(env_h.vseqr_h);    
    end
    #100;
    phase.drop_objection(this);
  endtask    
endclass

class gmii_eth_runt_good_fcs_test extends eth_test;
  `uvm_component_utils(gmii_eth_runt_good_fcs_test)
  
  function new (string name = "gmii_eth_runt_good_fcs_test", uvm_component parent = null);
    super.new(name,parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction    
  
  task run_phase(uvm_phase phase);
    virtual_seq vseq;
    
    phase.raise_objection(this);  
    repeat(this.no_of_pkts) begin
      vseq = virtual_seq::type_id::create("vseq");
      vseq.mode = 1;
      vseq.payload_rand_en = 0;
      vseq.runt_en = 1;
      vseq.padding_en = 0;
      vseq.start(env_h.vseqr_h);    
    end
    #100;
    phase.drop_objection(this);
  endtask    
endclass

class gmii_eth_runt_bad_fcs_test extends eth_test;
  `uvm_component_utils(gmii_eth_runt_bad_fcs_test)
  
  function new (string name = "gmii_eth_runt_bad_fcs_test", uvm_component parent = null);
    super.new(name,parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction    
  
  task run_phase(uvm_phase phase);
    virtual_seq vseq;
    
    phase.raise_objection(this);  
    repeat(this.no_of_pkts) begin
      vseq = virtual_seq::type_id::create("vseq");
      vseq.mode = 1;
      vseq.payload_rand_en = 0;
      vseq.runt_en = 1;
      vseq.corrupt_fcs_en = 1;
      vseq.padding_en =0;
      vseq.start(env_h.vseqr_h);    
    end
    #100;
    phase.drop_objection(this);
  endtask    
endclass


class gmii_eth_bad_fcs_test extends eth_test;
  `uvm_component_utils(gmii_eth_bad_fcs_test)
  
  function new (string name = "gmii_eth_bad_fcs_test", uvm_component parent = null);
    super.new(name,parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction    
  
  task run_phase(uvm_phase phase);
    virtual_seq vseq;
    
    phase.raise_objection(this);  
    vseq = virtual_seq::type_id::create("vseq");    
    vseq.error_pkt_no = $urandom_range(1, no_of_pkts);    
    repeat(this.no_of_pkts) begin
      vseq.mode = 1;
      vseq.payload_rand_en = 1;
      vseq.corrupt_fcs_en = 1;
      vseq.padding_en =1;
      vseq.start(env_h.vseqr_h);    
    end
    #100;
    phase.drop_objection(this);
  endtask    
endclass

class gmii_eth_vlan_reserved_vlanid_test extends eth_test;
  `uvm_component_utils(gmii_eth_vlan_reserved_vlanid_test)
  
  function new (string name = "gmii_eth_vlan_reserved_vlanid_test", uvm_component parent = null);
    super.new(name,parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction    
  
  task run_phase(uvm_phase phase);
    virtual_seq vseq;
    
    phase.raise_objection(this);  
    repeat(this.no_of_pkts) begin
      vseq = virtual_seq::type_id::create("vseq");
      vseq.mode = 1;
      vseq.vlan_en = 1;
      vseq.payload_rand_en = 1;
      vseq.TPID = 16'h8100;
      vseq.VID = 12'hFFF;
      vseq.padding_en =1;
      vseq.start(env_h.vseqr_h);    
    end
    #100;
    phase.drop_objection(this);
  endtask    
  
endclass


class gmii_eth_invalid_dest_addr_test extends eth_test;
  `uvm_component_utils(gmii_eth_invalid_dest_addr_test)
  
  function new (string name = "gmii_eth_invalid_dest_addr_test", uvm_component parent = null);
    super.new(name,parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction    
  
  task run_phase(uvm_phase phase);
    virtual_seq vseq;
    
    phase.raise_objection(this);  
    repeat(this.no_of_pkts) begin
      vseq = virtual_seq::type_id::create("vseq");
      vseq.mode = 1;
      vseq.payload_rand_en = 1;
      vseq.custom_da = 1;
      
      for (int i = 0; i < 6; i++)
      	vseq.da[8*i +: 8] = 8'h88;
      vseq.padding_en =1;
      vseq.start(env_h.vseqr_h);    
    end
    #100;
    phase.drop_objection(this);
  endtask    
  
endclass



class gmii_eth_normal_frame_undefined_length_test extends eth_test;
  `uvm_component_utils(gmii_eth_normal_frame_undefined_length_test)
  
  function new (string name = "gmii_eth_normal_frame_undefined_length_test", uvm_component parent = null);
    super.new(name,parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction    
  
  task run_phase(uvm_phase phase);
    virtual_seq vseq;
    
    phase.raise_objection(this);  
    repeat(this.no_of_pkts) begin
      vseq = virtual_seq::type_id::create("vseq");
      vseq.mode = 1;
      vseq.payload_rand_en = 0;
      vseq.invld_length_en = 1;
      vseq.padding_en =1;
      vseq.start(env_h.vseqr_h);    
    end
    #100;
    phase.drop_objection(this);
  endtask    
  
endclass


class gmii_eth_collision_detect_test extends eth_test;
  `uvm_component_utils(gmii_eth_collision_detect_test)
  
  function new (string name = "gmii_eth_collision_detect_test", uvm_component parent = null);
    super.new(name,parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction    
  
  task run_phase(uvm_phase phase);
    virtual_seq vseq;
    
    phase.raise_objection(this);  
    repeat(this.no_of_pkts) begin
      vseq = virtual_seq::type_id::create("vseq");
      vseq.mode = 0;
      vseq.payload_rand_en = 1;
      vseq.coll_en = 1;  
      vseq.padding_en =1;
      vseq.start(env_h.vseqr_h);    
    end
    #100;
    phase.drop_objection(this);
  endtask    
  
endclass


class gmii_eth_ipg_violation_test extends eth_test;
  `uvm_component_utils(gmii_eth_ipg_violation_test)
  
  function new (string name = "gmii_eth_ipg_violation_test", uvm_component parent = null);
    super.new(name,parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction    
  
  task run_phase(uvm_phase phase);
    virtual_seq vseq;
    
    phase.raise_objection(this);  
    vseq = virtual_seq::type_id::create("vseq");
    vseq.error_pkt_no = 5;
    repeat(this.no_of_pkts) begin
      vseq.mode = 1;
      vseq.payload_rand_en = 0;
      vseq.corrupt_ipg_en = 1;
      vseq.padding_en =1;
      vseq.start(env_h.vseqr_h);    
    end
    phase.drop_objection(this);
  endtask    
  
endclass


class gmii_eth_len_payload_mismat_test extends eth_test;
  `uvm_component_utils(gmii_eth_len_payload_mismat_test)
  
  function new (string name = "gmii_eth_len_payload_mismat_test", uvm_component parent = null);
    super.new(name,parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction    
  
  task run_phase(uvm_phase phase);
    virtual_seq vseq;
    
    phase.raise_objection(this);  
      vseq = virtual_seq::type_id::create("vseq");
      vseq.error_pkt_no = 2;
    repeat(this.no_of_pkts) begin
      vseq.mode = 1;      
      vseq.payload_rand_en = 1;
      vseq.len_payload_mismat_en=1;  
      vseq.padding_en =1;
      vseq.start(env_h.vseqr_h);    
    end
    #100;
    phase.drop_objection(this);
  endtask    
  
endclass


class gmii_eth_normal_payload_padding_test extends eth_test;
  `uvm_component_utils(gmii_eth_normal_payload_padding_test)
  
  function new (string name = "gmii_eth_normal_payload_padding_test", uvm_component parent = null);
    super.new(name, parent);
  endfunction
  
  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction  

  task run_phase(uvm_phase phase);
    virtual_seq vseq;
    
    phase.raise_objection(this);
    repeat(this.no_of_pkts) begin
      vseq = virtual_seq::type_id::create("vseq");
      vseq.mode = 1;
      vseq.ether_type = 40;
      vseq.padding_en =1;
      vseq.start(env_h.vseqr_h);
    end
    #100;
    phase.drop_objection(this);
  endtask  
endclass


class gmii_eth_vlan_payload_padding_test extends eth_test;
  `uvm_component_utils(gmii_eth_vlan_payload_padding_test)
  
  function new (string name = "gmii_eth_vlan_payload_padding_test", uvm_component parent = null);
    super.new(name,parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction    
  
  task run_phase(uvm_phase phase);
    virtual_seq vseq;
    
    phase.raise_objection(this);  
    repeat(this.no_of_pkts) begin
      vseq = virtual_seq::type_id::create("vseq");
      vseq.mode = 1;
      vseq.vlan_en = 1;
      vseq.payload_rand_en = 0;
      vseq.ether_type = 36;
      vseq.TPID = 16'h8100;  
      vseq.padding_en =1;
      vseq.start(env_h.vseqr_h);    
    end
    #100;
    phase.drop_objection(this);
  endtask    
  
endclass


class gmii_eth_vlan_same_vid_different_pcp_test extends eth_test;
  `uvm_component_utils(gmii_eth_vlan_same_vid_different_pcp_test)
  
  function new (string name = "gmii_eth_vlan_same_vid_different_pcp_test", uvm_component parent = null);
    super.new(name,parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction    
  
  task run_phase(uvm_phase phase);
    virtual_seq vseq;
    
    phase.raise_objection(this); 
    for(int i=0; i<this.no_of_pkts;i++)  begin
    	vseq = virtual_seq::type_id::create("vseq");
    	vseq.mode = 1;
    	vseq.vlan_en = 1;
      	vseq.ether_type=200;
    	vseq.payload_rand_en = 0;
    	vseq.TPID = 16'h8100;
        vseq.VID = 12'h64;
      
      	vseq.pcp = i%8;
    	
    	vseq.start(env_h.vseqr_h);
    end  
    #100;
    phase.drop_objection(this);
  endtask    
  
endclass



class gmii_eth_pfc_frame_test extends eth_test;
  `uvm_component_utils(gmii_eth_pfc_frame_test)
  
  function new (string name = "gmii_eth_pfc_frame_test", uvm_component parent = null);
    super.new(name,parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction    
  
  task run_phase(uvm_phase phase);
    virtual_seq vseq;
    
    phase.raise_objection(this); 
   
    vseq = virtual_seq::type_id::create("vseq");
    vseq.mode = 1;
    vseq.pfc_with_vlan_traffic =1;
    vseq.no_of_pkts = no_of_pkts;
    //vseq.pause_normal_traffic  =0;
    vseq.payload_rand_en = 0;
    vseq.ether_type = 46;
    vseq.vlan_en=1;
    vseq.start(env_h.vseqr_h);
    phase.drop_objection(this);
     
  endtask    
endclass



class gmii_eth_collision_in_middle_bytes_test extends eth_test;
  `uvm_component_utils(gmii_eth_collision_in_middle_bytes_test)
  
  function new (string name = "gmii_eth_collision_in_middle_bytes_test", uvm_component parent = null);
    super.new(name,parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction    
  
  task run_phase(uvm_phase phase);
    virtual_seq vseq;
    
    phase.raise_objection(this);  
    repeat(this.no_of_pkts) begin
      vseq = virtual_seq::type_id::create("vseq");    
      vseq.mode = 0;
      vseq.payload_rand_en = 1;
      vseq.coll_en = 1;  
      vseq.middle_coll_en = 1;
      vseq.padding_en =1;
      vseq.start(env_h.vseqr_h);    
    end
    #100;
    phase.drop_objection(this);
  endtask    
  
endclass


class gmii_eth_broadcast_frame_test extends eth_test;
  `uvm_component_utils(gmii_eth_broadcast_frame_test)
  
  function new (string name = "gmii_eth_broadcast_frame_test", uvm_component parent = null);
    super.new(name,parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction    
  
  task run_phase(uvm_phase phase);
    virtual_seq vseq;   
    phase.raise_objection(this);  
    repeat(this.no_of_pkts) begin
      vseq = virtual_seq::type_id::create("vseq");
      vseq.mode = 1;
      vseq.payload_rand_en = 1;
      vseq.custom_da = 1;
      vseq.da = 48'hFF_FF_FF_FF_FF_FF;
      vseq.padding_en =1;
      vseq.start(env_h.vseqr_h);    
    end
    #100;
    phase.drop_objection(this);
  endtask    
  
endclass


class gmii_eth_jabber_frame_test extends eth_test;
  `uvm_component_utils(gmii_eth_jabber_frame_test)
  
  function new (string name = "gmii_eth_jabber_frame_test", uvm_component parent = null);
    super.new(name,parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction    
  
  task run_phase(uvm_phase phase);
    virtual_seq vseq;   
    phase.raise_objection(this);  
    repeat(this.no_of_pkts) begin
      vseq = virtual_seq::type_id::create("vseq");
      vseq.mode = 1;
      vseq.payload_rand_en = 0;
      vseq.padding_en =1;
      vseq.corrupt_fcs_en = 1;
      vseq.ether_type = $urandom_range(1522, 2000);
      vseq.start(env_h.vseqr_h);    
    end
    #100;
    phase.drop_objection(this);
  endtask    
  
endclass


class gmii_eth_pause_frame_basic_xon_xoff_test extends eth_test;
  `uvm_component_utils(gmii_eth_pause_frame_basic_xon_xoff_test)

  function new (string name = "gmii_eth_pause_frame_basic_xon_xoff_test", uvm_component parent = null);
    super.new(name,parent);
  endfunction

 

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction    

  task run_phase(uvm_phase phase);
    virtual_seq vseq;

    phase.raise_objection(this);          
    vseq = virtual_seq::type_id::create("vseq");
    vseq.mode = 1;
    vseq.no_of_pkts = no_of_pkts;
    vseq.ether_type = 46;
    vseq.payload_rand_en = 0;
    vseq.pause_normal_traffic = 1;
    vseq.start(env_h.vseqr_h);
    phase.phase_done.set_drain_time(this,100);
    phase.drop_objection(this);

  endtask    
endclass

class gmii_eth_simultaneous_pause_frame_test extends eth_test;
  `uvm_component_utils(gmii_eth_simultaneous_pause_frame_test )

  function new (string name = "gmii_eth_simultaneous_pause_frame_test ", uvm_component parent = null);
    super.new(name,parent);
  endfunction

 

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction    

  task run_phase(uvm_phase phase);
    virtual_seq vseq;

    phase.raise_objection(this);          
    vseq = virtual_seq::type_id::create("vseq");
    vseq.mode = 1;
    vseq.no_of_pkts = no_of_pkts;
    vseq.payload_rand_en = 0;
    vseq.ether_type = 46;
    vseq.pause_normal_traffic = 1;
    vseq.start(env_h.vseqr_h);
    phase.phase_done.set_drain_time(this,100);
    phase.drop_objection(this);

  endtask    
endclass


class gmii_eth_pause_reserved_opcode_test extends eth_test;
  `uvm_component_utils(gmii_eth_pause_reserved_opcode_test)
  function new (string name = "gmii_eth_pause_reserved_opcode_test", uvm_component parent = null);
    super.new(name,parent);
  endfunction
 
  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction    
   task run_phase(uvm_phase phase);
    virtual_seq vseq;
    phase.raise_objection(this); 
      vseq = virtual_seq::type_id::create("vseq");
      vseq.mode = 1;
      vseq.no_of_pkts = no_of_pkts;
      vseq.payload_rand_en = 1;
      vseq.pause_normal_traffic=1;
      vseq.pfc_with_vlan_traffic =0;
      vseq.pause_rsd_en=1;
      vseq.start(env_h.vseqr_h);
      phase.phase_done.set_drain_time(this,100);
    phase.drop_objection(this);
  endtask    
endclass

class gmii_eth_multicast_frame_test extends eth_test;
  `uvm_component_utils(gmii_eth_multicast_frame_test)
  
  function new (string name = "gmii_eth_multicast_frame_test", uvm_component parent = null);
    super.new(name,parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
  endfunction    
  
  task run_phase(uvm_phase phase);
    virtual_seq vseq;   
    phase.raise_objection(this);  
    repeat(this.no_of_pkts) begin
      vseq = virtual_seq::type_id::create("vseq");
      vseq.mode = 1;
      vseq.payload_rand_en = 1;
      vseq.multicast_en = 1;
      vseq.custom_da = 1;
      vseq.da = 48'h01_50_40_30_20_10;
      vseq.padding_en =1;
      vseq.start(env_h.vseqr_h);    
    end
    #100;
    phase.drop_objection(this);
  endtask    
  
endclass
