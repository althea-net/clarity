// Non-opcode gas prices
pub const GDEFAULT: u32 = 1;
pub const GMEMORY: u32 = 3;
pub const GQUADRATICMEMDENOM: u32 = 512; // 1 gas per 512 quadwords
pub const GEXPONENTBYTE: u32 = 10; // cost of EXP exponent per byte
pub const GCOPY: u32 = 3; // cost to copy one 32 byte word
pub const GCONTRACTBYTE: u32 = 200; // one byte of code in contract creation
pub const GCALLVALUETRANSFER: u32 = 9000; // non-zero-valued call
pub const GLOGBYTE: u32 = 8; // cost of a byte of logdata

pub const GTXCOST: u32 = 21000; // TX BASE GAS COST
pub const GTXDATAZERO: u32 = 4; // TX DATA ZERO BYTE GAS COST
pub const GTXDATANONZERO: u32 = 68; // TX DATA NON ZERO BYTE GAS COST
pub const GSHA3WORD: u32 = 6; // Cost of SHA3 per word
pub const GSHA256BASE: u32 = 60; // Base c of SHA256
pub const GSHA256WORD: u32 = 12; // Cost of SHA256 per word
pub const GRIPEMD160BASE: u32 = 600; // Base cost of RIPEMD160
pub const GRIPEMD160WORD: u32 = 120; // Cost of RIPEMD160 per word
pub const GIDENTITYBASE: u32 = 15; // Base cost of indentity
pub const GIDENTITYWORD: u32 = 3; // Cost of identity per word
pub const GECRECOVER: u32 = 3000; // Cost of ecrecover op

pub const GSTIPEND: u32 = 2300;

pub const GCALLNEWACCOUNT: u32 = 25000;
pub const GSUICIDEREFUND: u32 = 24000;

pub const GSTORAGEBASE: u32 = 2500;
pub const GSTORAGEBYTESTORAGE: u32 = 250;
pub const GSTORAGEBYTECHANGE: u32 = 40;
pub const GSTORAGEMIN: u32 = 2500;
pub const GSSIZE: u32 = 50;
pub const GSLOADBYTES: u32 = 50;

pub const GSTORAGEREFUND: u32 = 15000;
pub const GSTORAGEKILL: u32 = 5000;
pub const GSTORAGEMOD: u32 = 5000;
pub const GSTORAGEADD: u32 = 20000;

pub const GMODEXPQUADDIVISOR: u32 = 20;
pub const GECADD: u32 = 500;
pub const GECMUL: u32 = 40000;

pub const GPAIRINGBASE: u32 = 100000;
pub const GPAIRINGPERPOINT: u32 = 80000;
