class eth_virtual_seqr extends uvm_sequencer #(eth_seq_item);
  `uvm_component_utils(eth_virtual_seqr)

  eth_seqr mac[];

  function new(string name = "eth_virtual_seqr", uvm_component parent = null);
    super.new(name, parent);
    
    mac = new[`NO_OF_AGENTS];
    
  endfunction
  
endclass
