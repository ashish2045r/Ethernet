class base_virtual_seq extends uvm_sequence;
  `uvm_object_utils(base_virtual_seq)

  int ether_type;
  bit err_b;
  int err_offset;
  bit [47:0] da;
  bit vlan_en;
  bit [15:0] TPID;
  bit payload_rand_en;
  bit corrupt_preamble_en;
  bit multicast_en = 0;
  bit broadcast_en = 0;

  int unsigned custom_err_offset;
  bit custom_err_b;

  bit custom_vlan_en;
  bit [15:0] custom_TPID; 

  bit pause_frame_en;
  bit [15:0] pause_opc;
  bit [15:0] pause_time;  
  bit mode;
  bit corrupt_fcs_en;
  bit custom_da;
  bit [11:0] VID;
  bit invld_length_en;
  bit carr_ext_en;
  bit runt_en;
  bit coll_en;
  bit len_payload_mismat_en;   
  bit corrupt_ipg_en;
  int set_corpt_pkt;
  int error_pkt_no;
  bit padding_en;
  bit [2:0]pcp; 
  bit pfc_frame_en;   
  bit pfc_with_vlan_traffic;
  bit pause_normal_traffic ;
  int no_of_pkts;
  int count;
  int scount;
  bit pause_rsd_en;
  bit pause_update_time_en;
  bit middle_coll_en;  

  function new (string name = "base_virtual_seq");
    super.new(name);
  endfunction  



endclass

class virtual_seq extends base_virtual_seq;
  `uvm_object_utils(virtual_seq)
  `uvm_declare_p_sequencer(eth_virtual_seqr)

  gmii_eth_normal_frame_seq seq1, seq2;  


  function new (string name = "virtual_seq");
    super.new(name);
  endfunction  

  task body();

    if(!pause_normal_traffic && ! pfc_with_vlan_traffic) begin

      seq1 = gmii_eth_normal_frame_seq::type_id::create("seq1");
      seq2 = gmii_eth_normal_frame_seq::type_id::create("seq2");

      // Configure sequences config variables received from test
      apply_config(seq1);
      apply_config(seq2);

      // Start only one sequence for multicast and collision testcases
      if((this.mode == 0 && !coll_en) || multicast_en || broadcast_en) begin
        seq1.start(p_sequencer.mac_seqr_h[0]);
      end
      // Start two sequences in parallel
      else begin
        fork
          seq1.start(p_sequencer.mac_seqr_h[0]);
          seq2.start(p_sequencer.mac_seqr_h[1]);
        join
      end
    end

    else begin

      if(mode==1) begin

        //------------------pause normal traffic--------------

        if(pause_normal_traffic) begin

          fork
          begin
            repeat(this.no_of_pkts) begin
              seq1 = gmii_eth_normal_frame_seq::type_id::create("seq1");
              apply_config(seq1);

              if(count==3 || count==5 ) begin
                seq1.pause_sel = 1;
                seq1.pause_time=10;
                seq1.pause_rsd_en =this.pause_rsd_en;
              end

              else if(this.pause_update_time_en  && ((count==4) ||( count==5) ||( count==7)) ) begin
                seq1.pause_sel =1;
                seq1.pause_time=$urandom_range(1,10);
              end

              else if(count==10 && !pause_update_time_en ) begin
                seq1.pause_sel=1;
                seq1.pause_time=100;
              end

              else if(count==12 && !pause_update_time_en ) begin
                seq1.pause_sel=1;
                seq1.pause_time=0;
              end

              else
                seq1.pause_sel=0;
              
              seq1.start(p_sequencer.mac_seqr_h[0]);
              count++;
            end
          end
          begin
            repeat(this.no_of_pkts) begin
              seq2 = gmii_eth_normal_frame_seq::type_id::create("seq2");
              apply_config(seq2);
              if(scount==3 || scount==5) begin
                seq2.pause_sel=1;
                seq2.pause_time=10;
                seq2.pause_rsd_en = this.pause_rsd_en;
              end

              else
                seq2.pause_sel = 0;//($urandom_range(1,2) % 2);
              seq2.start(p_sequencer.mac_seqr_h[1]);
              scount++;
            end
          end
          join
        end 

        //---------------- VLAN TRAFFIC+pfc ----------------   
        if(pfc_with_vlan_traffic) begin

          fork

          begin
            repeat(this.no_of_pkts) begin

              seq1 = gmii_eth_normal_frame_seq::type_id::create
              ($sformatf("vlan_seq_%0d",$time));

              apply_config(seq1);
              if(count==3) begin
                seq1.pfc_sel=1;	
              end  
              else
                seq1.pfc_sel = 0;
              seq1.start(p_sequencer.mac_seqr_h[0]);
              count++;
            end
          end
          begin
            repeat(this.no_of_pkts) begin

              seq2 = gmii_eth_normal_frame_seq::type_id::create
              ($sformatf("pfc_seq_%0d",$time));

              apply_config(seq2);
              seq2.pfc_sel =0;
              seq2.start(p_sequencer.mac_seqr_h[1]);
            end
          end
          join
        end
      end
    end
  endtask

  //Applying config values for virtual seq to sequence
  task apply_config(ref gmii_eth_normal_frame_seq seq);
    seq.pkt_no              = this.set_corpt_pkt;
    seq.c_ether_type        = this.ether_type;
    seq.err_b               = this.err_b;
    seq.err_offset          = this.err_offset;
    seq.vlan_en             = this.vlan_en;
    seq.TPID                = this.TPID;
    seq.payload_rand_en     = this.payload_rand_en;
    // seq.pause_frame_en      = this.pause_frame_en;
    // seq.pause_opc           = this.pause_opc;
    seq.corrupt_preamble_en = this.corrupt_preamble_en;
    seq.mode                = this.mode;
    seq.corrupt_fcs_en      = this.corrupt_fcs_en;
    seq.custom_da           = this.custom_da;  
    seq.da                  = this.da;
    seq.VID                 = this.VID;    
    seq.invld_length_en     = this.invld_length_en;
    seq.carr_ext_en         = this.carr_ext_en;
    seq.runt_en				= this.runt_en;
    seq.len_payload_mismat_en = this.len_payload_mismat_en; 
    seq.corrupt_ipg_en      = this.corrupt_ipg_en;
    seq.error_pkt_no        = this.error_pkt_no;
    seq.padding_en          = this.padding_en;
    seq.pause_rsd_en       = this.pause_rsd_en ; 
  endtask   

endclass


