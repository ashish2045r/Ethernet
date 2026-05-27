class globals;
 
  static virtual eth_ui_interface v_uif[bit[47:0]];
 
  //pause
  static int  pause_value [bit[47:0]];
  static bit  pause_flag  [`NO_OF_AGENTS];
  static bit  pause_update[2];
 
  //pfc
  static int  pfc_value   [int][8];
  static bit  pfc_flag    [`NO_OF_AGENTS][8];
  static bit  pfc_active  [`NO_OF_AGENTS][8];
endclass
