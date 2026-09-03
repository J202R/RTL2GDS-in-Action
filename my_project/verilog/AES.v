
module AES #(parameter Nk = 1, parameter Nr = 5) (
    clk,
    reset_n,
    in,
    key,
    round_keys,
    encryption_out,
    decryption_out,
    encryption_done,
    decryption_done
);
localparam Nb = 1;
localparam WORD_SIZE = 32;
localparam NUMBER_OF_GENERATED_WORDS = Nb * (Nr + 1);
localparam ROUND_KEYS_SIZE = WORD_SIZE * NUMBER_OF_GENERATED_WORDS;
localparam KEY_SIZE = Nk * WORD_SIZE;
localparam BLOCK_SIZE = 32;

input clk;
input reset_n;
input [BLOCK_SIZE - 1 : 0] in;
input [KEY_SIZE - 1 : 0] key;
output [BLOCK_SIZE - 1 : 0] encryption_out;
output [BLOCK_SIZE - 1 : 0] decryption_out;
output encryption_done, decryption_done;
output wire [ROUND_KEYS_SIZE - 1 : 0] round_keys;

KeyExpansion #(.Nk(Nk), .Nr(Nr)) KeyExpansion_instance(
    .key_in(key),
    .round_keys(round_keys)
);

Cipher #(.Nk(Nk), .Nr(Nr)) Cipher_instance(
    .clk(clk),
    .reset_n(reset_n),
    .in(in),
    .round_keys(round_keys),
    .out(encryption_out),
    .done(encryption_done)
);

InvCipher #(.Nk(Nk), .Nr(Nr)) InvCipher_instance(
    .clk(clk),
    .reset_n(reset_n),
    .in(encryption_out),
    .round_keys(round_keys),
    .out(decryption_out),
    .done(decryption_done)
);
endmodule

// ============================================================================
// AddRoundKey - XOR con la clave de ronda
// ============================================================================
module AddRoundKey (in, out, key);
    input [31:0] in;
    input [31:0] key;
    output [31:0] out;
    
    assign out = in ^ key;
endmodule

// ============================================================================
// Cipher - Proceso de encriptación
// ============================================================================
module Cipher #(parameter Nk = 1, parameter Nr = 5) (clk, reset_n, in, round_keys, out, done);
localparam Nb = 1;
localparam WORD_SIZE = 32;
localparam KEY_SIZE = 32;
localparam BLOCK_SIZE = 32;
localparam INPUT_KEY_SIZE = Nk * WORD_SIZE;
localparam NUMBER_OF_GENERATED_WORDS = Nb * (Nr + 1);
localparam ROUND_KEYS_SIZE = WORD_SIZE * NUMBER_OF_GENERATED_WORDS;

input clk, reset_n;
input [BLOCK_SIZE - 1 : 0] in;
input [ROUND_KEYS_SIZE - 1 : 0] round_keys;
output [BLOCK_SIZE - 1 : 0] out;
output done;

reg [BLOCK_SIZE - 1 : 0] ARK_in, state_reg;
wire [BLOCK_SIZE-1:0] ARK_out, SB_out, SR_out, MC_out, state_next;
reg [KEY_SIZE-1:0] ARK_key;

SubBytes SB(.in(state_reg), .out(SB_out));
ShiftRows SR(.in(SB_out), .out(SR_out));
MixColumns MC(.in(SR_out), .out(MC_out));
AddRoundKey ARK(.in(ARK_in), .key(ARK_key), .out(state_next));

reg [3:0] i, i_next;

always @(*) begin
    i_next = (i == Nr) ? 0 : i + 1;
    ARK_key = round_keys[ROUND_KEYS_SIZE - i * KEY_SIZE - 1 -: KEY_SIZE];
    ARK_in = (i == 1'b0) ? in : (i == Nr) ? SR_out : MC_out;
end

always @(posedge clk, negedge reset_n) begin
    if(~reset_n) begin
        state_reg <= 0;
    end else begin
        state_reg <= state_next;
    end
end

always @(negedge clk, negedge reset_n) begin
    if(~reset_n) begin
        i <= 0;
    end else begin
        i <= i_next;
    end
end

assign out = state_reg;
assign done = (i == Nr) ? 1'b1 : 1'b0;
endmodule

// ============================================================================
// InvCipher - Proceso de desencriptación
// ============================================================================
module InvCipher #(parameter Nk = 1, parameter Nr = 5) (clk, reset_n, in, round_keys, out, done);
localparam Nb = 1;
localparam WORD_SIZE = 32;
localparam KEY_SIZE = 32;
localparam BLOCK_SIZE = 32;
localparam INPUT_KEY_SIZE = Nk * WORD_SIZE;
localparam NUMBER_OF_GENERATED_WORDS = Nb * (Nr + 1);
localparam ROUND_KEYS_SIZE = WORD_SIZE * NUMBER_OF_GENERATED_WORDS;

input clk, reset_n;
input [BLOCK_SIZE - 1 : 0] in;
input [ROUND_KEYS_SIZE - 1 : 0] round_keys;
output [BLOCK_SIZE - 1 : 0] out;
output done;

reg [KEY_SIZE - 1:0] ARK_key;
reg [BLOCK_SIZE - 1 : 0] ARK_in, state_reg, state_next;
wire [BLOCK_SIZE-1:0] ARK_out, ISB_out, ISR_out, IMC_out;

InvShiftRows ISR(.in(state_reg), .out(ISR_out));
InvSubBytes ISB(.in(ISR_out), .out(ISB_out));
AddRoundKey ARK(.in(ARK_in), .key(ARK_key), .out(ARK_out));
InvMixColumns IMC(.in(ARK_out), .out(IMC_out));

reg [3:0] i, i_next;

always @(*) begin
    i_next = (i == Nr) ? 0 : i + 1;
    ARK_key = round_keys[KEY_SIZE * (i + 1) - 1 -: KEY_SIZE];
    ARK_in = (i == 0) ? in : ISB_out;
    state_next = (i == Nr || i == 0) ? ARK_out : IMC_out;
end

always @(posedge clk, negedge reset_n) begin
    if(~reset_n) begin
        state_reg <= 0;
    end else begin
        state_reg <= state_next;
    end     
end

always @(negedge clk, negedge reset_n) begin
    if(~reset_n) begin
        i <= 0;
    end else begin
        i <= i_next;
    end
end

assign out = state_reg;
assign done = (i == Nr) ? 1 : 0;
endmodule

// ============================================================================
// MixColumns - Mezcla de columnas (versión 32-bit)
// ============================================================================
module MixColumns(in, out);
input [31:0] in;
output [31:0] out;

function [7:0] mul2;
    input [7:0] a;
    begin
        if(a[7] == 1) begin
            mul2 = (a << 1) ^ 8'h1b;
        end
        else begin
            mul2 = a << 1;
        end
    end
endfunction

function [7:0] mul3;
    input [7:0] a;
    begin
        mul3 = mul2(a) ^ a;
    end
endfunction

// Para 32 bits (4 bytes), aplicamos la matriz de mezcla simplificada
assign out[31:24] = mul2(in[31:24]) ^ mul3(in[23:16]) ^ in[15:8] ^ in[7:0];
assign out[23:16] = in[31:24] ^ mul2(in[23:16]) ^ mul3(in[15:8]) ^ in[7:0];
assign out[15:8]  = in[31:24] ^ in[23:16] ^ mul2(in[15:8]) ^ mul3(in[7:0]);
assign out[7:0]   = mul3(in[31:24]) ^ in[23:16] ^ in[15:8] ^ mul2(in[7:0]);

endmodule

// ============================================================================
// InvMixColumns - Mezcla inversa de columnas (versión 32-bit)
// ============================================================================
module InvMixColumns(in, out);
input [31:0] in;
output [31:0] out;

function [7:0] mul2;
    input [7:0] a;
    begin
        if(a[7] == 1) begin
            mul2 = (a << 1) ^ 8'h1b;
        end
        else begin
            mul2 = a << 1;
        end
    end
endfunction

function [7:0] mul3;
    input [7:0] a;
    begin
        mul3 = mul2(a) ^ a;
    end
endfunction

function [7:0] mul0b;
    input [7:0] a;
    begin
        mul0b = mul2(mul2(mul2(a))) ^ mul2(a) ^ a;
    end
endfunction

function [7:0] mul0d;
    input [7:0] a;
    begin
        mul0d = mul2(mul2(mul2(a))) ^ mul2(mul2(a)) ^ a;
    end
endfunction

function [7:0] mul09;
    input [7:0] a;
    begin
        mul09 = mul2(mul2(mul2(a))) ^ a;
    end
endfunction

function [7:0] mul0e;
    input [7:0] a;
    begin
        mul0e = mul2(mul2(mul2(a))) ^ mul2(mul2(a)) ^ mul2(a);
    end
endfunction

assign out[31:24] = mul0e(in[31:24]) ^ mul0b(in[23:16]) ^ mul0d(in[15:8]) ^ mul09(in[7:0]);
assign out[23:16] = mul09(in[31:24]) ^ mul0e(in[23:16]) ^ mul0b(in[15:8]) ^ mul0d(in[7:0]);
assign out[15:8]  = mul0d(in[31:24]) ^ mul09(in[23:16]) ^ mul0e(in[15:8]) ^ mul0b(in[7:0]);
assign out[7:0]   = mul0b(in[31:24]) ^ mul0d(in[23:16]) ^ mul09(in[15:8]) ^ mul0e(in[7:0]);

endmodule

// ============================================================================
// ShiftRows - Desplazamiento de filas (versión 32-bit simplificada)
// ============================================================================
module ShiftRows(in, out);
input [31:0] in;
output [31:0] out;

// Para 32 bits, rotamos los bytes
assign out[31:24] = in[31:24];  // byte 0: sin cambio
assign out[23:16] = in[7:0];    // byte 1: del byte 3
assign out[15:8]  = in[23:16];  // byte 2: del byte 1
assign out[7:0]   = in[15:8];   // byte 3: del byte 2

endmodule

// ============================================================================
// InvShiftRows - Desplazamiento inverso de filas (versión 32-bit)
// ============================================================================
module InvShiftRows(in, out);
input [31:0] in;
output [31:0] out;

// Operación inversa de ShiftRows
assign out[31:24] = in[31:24];  // byte 0: sin cambio
assign out[23:16] = in[15:8];   // byte 1: del byte 2
assign out[15:8]  = in[7:0];    // byte 2: del byte 3
assign out[7:0]   = in[23:16];  // byte 3: del byte 1

endmodule

// ============================================================================
// SubBytes - Sustitución de bytes usando S-Box
// ============================================================================
module SubBytes(in, out);
    input [31:0] in;
    output [31:0] out;
    
    genvar i;
    generate
        for(i = 0; i < 32; i = i + 8)
        begin: sub_bytes
            SBox sBox_instance(in[i +: 8], out[i +: 8]);
        end
    endgenerate
endmodule

// ============================================================================
// InvSubBytes - Sustitución inversa de bytes
// ============================================================================
module InvSubBytes(in, out);
    input [31:0] in;
    output [31:0] out;
    
    genvar i;
    generate
        for(i = 0; i < 32; i = i + 8)
        begin: inv_sub_bytes
            InvSBox invSBox_instance(in[i +: 8], out[i +: 8]);
        end
    endgenerate
endmodule

// ============================================================================
// SBox - Tabla de sustitución (igual que AES-128)
// ============================================================================
module SBox(xy, xy_out);
    input [7:0] xy;
    output reg [7:0] xy_out;
    
    always @(xy) begin  
        case(xy)
            8'h00: xy_out = 8'h63;
            8'h01: xy_out = 8'h7c;
            8'h02: xy_out = 8'h77;
            8'h03: xy_out = 8'h7b;
            8'h04: xy_out = 8'hf2;
            8'h05: xy_out = 8'h6b;
            8'h06: xy_out = 8'h6f;
            8'h07: xy_out = 8'hc5;
            8'h08: xy_out = 8'h30;
            8'h09: xy_out = 8'h01;
            8'h0a: xy_out = 8'h67;
            8'h0b: xy_out = 8'h2b;
            8'h0c: xy_out = 8'hfe;
            8'h0d: xy_out = 8'hd7;
            8'h0e: xy_out = 8'hab;
            8'h0f: xy_out = 8'h76;
            8'h10: xy_out = 8'hca;
            8'h11: xy_out = 8'h82;
            8'h12: xy_out = 8'hc9;
            8'h13: xy_out = 8'h7d;
            8'h14: xy_out = 8'hfa;
            8'h15: xy_out = 8'h59;
            8'h16: xy_out = 8'h47;
            8'h17: xy_out = 8'hf0;
            8'h18: xy_out = 8'had;
            8'h19: xy_out = 8'hd4;
            8'h1a: xy_out = 8'ha2;
            8'h1b: xy_out = 8'haf;
            8'h1c: xy_out = 8'h9c;
            8'h1d: xy_out = 8'ha4;
            8'h1e: xy_out = 8'h72;
            8'h1f: xy_out = 8'hc0;
            8'h20: xy_out = 8'hb7;
            8'h21: xy_out = 8'hfd;
            8'h22: xy_out = 8'h93;
            8'h23: xy_out = 8'h26;
            8'h24: xy_out = 8'h36;
            8'h25: xy_out = 8'h3f;
            8'h26: xy_out = 8'hf7;
            8'h27: xy_out = 8'hcc;
            8'h28: xy_out = 8'h34;
            8'h29: xy_out = 8'ha5;
            8'h2a: xy_out = 8'he5;
            8'h2b: xy_out = 8'hf1;
            8'h2c: xy_out = 8'h71;
            8'h2d: xy_out = 8'hd8;
            8'h2e: xy_out = 8'h31;
            8'h2f: xy_out = 8'h15;
            8'h30: xy_out = 8'h04;
            8'h31: xy_out = 8'hc7;
            8'h32: xy_out = 8'h23;
            8'h33: xy_out = 8'hc3;
            8'h34: xy_out = 8'h18;
            8'h35: xy_out = 8'h96;
            8'h36: xy_out = 8'h05;
            8'h37: xy_out = 8'h9a;
            8'h38: xy_out = 8'h07;
            8'h39: xy_out = 8'h12;
            8'h3a: xy_out = 8'h80;
            8'h3b: xy_out = 8'he2;
            8'h3c: xy_out = 8'heb;
            8'h3d: xy_out = 8'h27;
            8'h3e: xy_out = 8'hb2;
            8'h3f: xy_out = 8'h75;
            8'h40: xy_out = 8'h09;
            8'h41: xy_out = 8'h83;
            8'h42: xy_out = 8'h2c;
            8'h43: xy_out = 8'h1a;
            8'h44: xy_out = 8'h1b;
            8'h45: xy_out = 8'h6e;
            8'h46: xy_out = 8'h5a;
            8'h47: xy_out = 8'ha0;
            8'h48: xy_out = 8'h52;
            8'h49: xy_out = 8'h3b;
            8'h4a: xy_out = 8'hd6;
            8'h4b: xy_out = 8'hb3;
            8'h4c: xy_out = 8'h29;
            8'h4d: xy_out = 8'he3;
            8'h4e: xy_out = 8'h2f;
            8'h4f: xy_out = 8'h84;
            8'h50: xy_out = 8'h53;
            8'h51: xy_out = 8'hd1;
            8'h52: xy_out = 8'h00;
            8'h53: xy_out = 8'hed;
            8'h54: xy_out = 8'h20;
            8'h55: xy_out = 8'hfc;
            8'h56: xy_out = 8'hb1;
            8'h57: xy_out = 8'h5b;
            8'h58: xy_out = 8'h6a;
            8'h59: xy_out = 8'hcb;
            8'h5a: xy_out = 8'hbe;
            8'h5b: xy_out = 8'h39;
            8'h5c: xy_out = 8'h4a;
            8'h5d: xy_out = 8'h4c;
            8'h5e: xy_out = 8'h58;
            8'h5f: xy_out = 8'hcf;
            8'h60: xy_out = 8'hd0;
            8'h61: xy_out = 8'hef;
            8'h62: xy_out = 8'haa;
            8'h63: xy_out = 8'hfb;
            8'h64: xy_out = 8'h43;
            8'h65: xy_out = 8'h4d;
            8'h66: xy_out = 8'h33;
            8'h67: xy_out = 8'h85;
            8'h68: xy_out = 8'h45;
            8'h69: xy_out = 8'hf9;
            8'h6a: xy_out = 8'h02;
            8'h6b: xy_out = 8'h7f;
            8'h6c: xy_out = 8'h50;
            8'h6d: xy_out = 8'h3c;
            8'h6e: xy_out = 8'h9f;
            8'h6f: xy_out = 8'ha8;
            8'h70: xy_out = 8'h51;
            8'h71: xy_out = 8'ha3;
            8'h72: xy_out = 8'h40;
            8'h73: xy_out = 8'h8f;
            8'h74: xy_out = 8'h92;
            8'h75: xy_out = 8'h9d;
            8'h76: xy_out = 8'h38;
            8'h77: xy_out = 8'hf5;
            8'h78: xy_out = 8'hbc;
            8'h79: xy_out = 8'hb6;
            8'h7a: xy_out = 8'hda;
            8'h7b: xy_out = 8'h21;
            8'h7c: xy_out = 8'h10;
            8'h7d: xy_out = 8'hff;
            8'h7e: xy_out = 8'hf3;
            8'h7f: xy_out = 8'hd2;
            8'h80: xy_out = 8'hcd;
            8'h81: xy_out = 8'h0c;
            8'h82: xy_out = 8'h13;
            8'h83: xy_out = 8'hec;
            8'h84: xy_out = 8'h5f;
            8'h85: xy_out = 8'h97;
            8'h86: xy_out = 8'h44;
            8'h87: xy_out = 8'h17;
            8'h88: xy_out = 8'hc4;
            8'h89: xy_out = 8'ha7;
            8'h8a: xy_out = 8'h7e;
            8'h8b: xy_out = 8'h3d;
            8'h8c: xy_out = 8'h64;
            8'h8d: xy_out = 8'h5d;
            8'h8e: xy_out = 8'h19;
            8'h8f: xy_out = 8'h73;
            8'h90: xy_out = 8'h60;
            8'h91: xy_out = 8'h81;
            8'h92: xy_out = 8'h4f;
            8'h93: xy_out = 8'hdc;
            8'h94: xy_out = 8'h22;
            8'h95: xy_out = 8'h2a;
            8'h96: xy_out = 8'h90;
            8'h97: xy_out = 8'h88;
            8'h98: xy_out = 8'h46;
            8'h99: xy_out = 8'hee;
            8'h9a: xy_out = 8'hb8;
            8'h9b: xy_out = 8'h14;
            8'h9c: xy_out = 8'hde;
            8'h9d: xy_out = 8'h5e;
            8'h9e: xy_out = 8'h0b;
            8'h9f: xy_out = 8'hdb;
            8'ha0: xy_out = 8'he0;
            8'ha1: xy_out = 8'h32;
            8'ha2: xy_out = 8'h3a;
            8'ha3: xy_out = 8'h0a;
            8'ha4: xy_out = 8'h49;
            8'ha5: xy_out = 8'h06;
            8'ha6: xy_out = 8'h24;
            8'ha7: xy_out = 8'h5c;
            8'ha8: xy_out = 8'hc2;
            8'ha9: xy_out = 8'hd3;
            8'haa: xy_out = 8'hac;
            8'hab: xy_out = 8'h62;
            8'hac: xy_out = 8'h91;
            8'had: xy_out = 8'h95;
            8'hae: xy_out = 8'he4;
            8'haf: xy_out = 8'h79;
            8'hb0: xy_out = 8'he7;
            8'hb1: xy_out = 8'hc8;
            8'hb2: xy_out = 8'h37;
            8'hb3: xy_out = 8'h6d;
            8'hb4: xy_out = 8'h8d;
            8'hb5: xy_out = 8'hd5;
            8'hb6: xy_out = 8'h4e;
            8'hb7: xy_out = 8'ha9;
            8'hb8: xy_out = 8'h6c;
            8'hb9: xy_out = 8'h56;
            8'hba: xy_out = 8'hf4;
            8'hbb: xy_out = 8'hea;
            8'hbc: xy_out = 8'h65;
            8'hbd: xy_out = 8'h7a;
            8'hbe: xy_out = 8'hae;
            8'hbf: xy_out = 8'h08;
            8'hc0: xy_out = 8'hba;
            8'hc1: xy_out = 8'h78;
            8'hc2: xy_out = 8'h25;
            8'hc3: xy_out = 8'h2e;
            8'hc4: xy_out = 8'h1c;
            8'hc5: xy_out = 8'ha6;
            8'hc6: xy_out = 8'hb4;
            8'hc7: xy_out = 8'hc6;
            8'hc8: xy_out = 8'he8;
            8'hc9: xy_out = 8'hdd;
            8'hca: xy_out = 8'h74;
            8'hcb: xy_out = 8'h1f;
            8'hcc: xy_out = 8'h4b;
            8'hcd: xy_out = 8'hbd;
            8'hce: xy_out = 8'h8b;
            8'hcf: xy_out = 8'h8a;
            8'hd0: xy_out = 8'h70;
            8'hd1: xy_out = 8'h3e;
            8'hd2: xy_out = 8'hb5;
            8'hd3: xy_out = 8'h66;
            8'hd4: xy_out = 8'h48;
            8'hd5: xy_out = 8'h03;
            8'hd6: xy_out = 8'hf6;
            8'hd7: xy_out = 8'h0e;
            8'hd8: xy_out = 8'h61;
            8'hd9: xy_out = 8'h35;
            8'hda: xy_out = 8'h57;
            8'hdb: xy_out = 8'hb9;
            8'hdc: xy_out = 8'h86;
            8'hdd: xy_out = 8'hc1;
            8'hde: xy_out = 8'h1d;
            8'hdf: xy_out = 8'h9e;
            8'he0: xy_out = 8'he1;
            8'he1: xy_out = 8'hf8;
            8'he2: xy_out = 8'h98;
            8'he3: xy_out = 8'h11;
            8'he4: xy_out = 8'h69;
            8'he5: xy_out = 8'hd9;
            8'he6: xy_out = 8'h8e;
            8'he7: xy_out = 8'h94;
            8'he8: xy_out = 8'h9b;
            8'he9: xy_out = 8'h1e;
            8'hea: xy_out = 8'h87;
            8'heb: xy_out = 8'he9;
            8'hec: xy_out = 8'hce;
            8'hed: xy_out = 8'h55;
            8'hee: xy_out = 8'h28;
            8'hef: xy_out = 8'hdf;
            8'hf0: xy_out = 8'h8c;
            8'hf1: xy_out = 8'ha1;
            8'hf2: xy_out = 8'h89;
            8'hf3: xy_out = 8'h0d;
            8'hf4: xy_out = 8'hbf;
            8'hf5: xy_out = 8'he6;
            8'hf6: xy_out = 8'h42;
            8'hf7: xy_out = 8'h68;
            8'hf8: xy_out = 8'h41;
            8'hf9: xy_out = 8'h99;
            8'hfa: xy_out = 8'h2d;
            8'hfb: xy_out = 8'h0f;
            8'hfc: xy_out = 8'hb0;
            8'hfd: xy_out = 8'h54;
            8'hfe: xy_out = 8'hbb;
            8'hff: xy_out = 8'h16;
        endcase
    end
endmodule

// ============================================================================
// InvSBox - Tabla de sustitución inversa (igual que AES-128)
// ============================================================================
module InvSBox(xy, xy_out);
    input [7:0] xy;
    output reg [7:0] xy_out;
    
    always @(xy) begin  
        case(xy)
            8'h00: xy_out = 8'h52;
            8'h01: xy_out = 8'h09;
            8'h02: xy_out = 8'h6a;
            8'h03: xy_out = 8'hd5;
            8'h04: xy_out = 8'h30;
            8'h05: xy_out = 8'h36;
            8'h06: xy_out = 8'ha5;
            8'h07: xy_out = 8'h38;
            8'h08: xy_out = 8'hbf;
            8'h09: xy_out = 8'h40;
            8'h0a: xy_out = 8'ha3;
            8'h0b: xy_out = 8'h9e;
            8'h0c: xy_out = 8'h81;
            8'h0d: xy_out = 8'hf3;
            8'h0e: xy_out = 8'hd7;
            8'h0f: xy_out = 8'hfb;
            8'h10: xy_out = 8'h7c;
            8'h11: xy_out = 8'he3;
            8'h12: xy_out = 8'h39;
            8'h13: xy_out = 8'h82;
            8'h14: xy_out = 8'h9b;
            8'h15: xy_out = 8'h2f;
            8'h16: xy_out = 8'hff;
            8'h17: xy_out = 8'h87;
            8'h18: xy_out = 8'h34;
            8'h19: xy_out = 8'h8e;
            8'h1a: xy_out = 8'h43;
            8'h1b: xy_out = 8'h44;
            8'h1c: xy_out = 8'hc4;
            8'h1d: xy_out = 8'hde;
            8'h1e: xy_out = 8'he9;
            8'h1f: xy_out = 8'hcb;
            8'h20: xy_out = 8'h54;
            8'h21: xy_out = 8'h7b;
            8'h22: xy_out = 8'h94;
            8'h23: xy_out = 8'h32;
            8'h24: xy_out = 8'ha6;
            8'h25: xy_out = 8'hc2;
            8'h26: xy_out = 8'h23;
            8'h27: xy_out = 8'h3d;
            8'h28: xy_out = 8'hee;
            8'h29: xy_out = 8'h4c;
            8'h2a: xy_out = 8'h95;
            8'h2b: xy_out = 8'h0b;
            8'h2c: xy_out = 8'h42;
            8'h2d: xy_out = 8'hfa;
            8'h2e: xy_out = 8'hc3;
            8'h2f: xy_out = 8'h4e;
            8'h30: xy_out = 8'h08;
            8'h31: xy_out = 8'h2e;
            8'h32: xy_out = 8'ha1;
            8'h33: xy_out = 8'h66;
            8'h34: xy_out = 8'h28;
            8'h35: xy_out = 8'hd9;
            8'h36: xy_out = 8'h24;
            8'h37: xy_out = 8'hb2;
            8'h38: xy_out = 8'h76;
            8'h39: xy_out = 8'h5b;
            8'h3a: xy_out = 8'ha2;
            8'h3b: xy_out = 8'h49;
            8'h3c: xy_out = 8'h6d;
            8'h3d: xy_out = 8'h8b;
            8'h3e: xy_out = 8'hd1;
            8'h3f: xy_out = 8'h25;
            8'h40: xy_out = 8'h72;
            8'h41: xy_out = 8'hf8;
            8'h42: xy_out = 8'hf6;
            8'h43: xy_out = 8'h64;
            8'h44: xy_out = 8'h86;
            8'h45: xy_out = 8'h68;
            8'h46: xy_out = 8'h98;
            8'h47: xy_out = 8'h16;
            8'h48: xy_out = 8'hd4;
            8'h49: xy_out = 8'ha4;
            8'h4a: xy_out = 8'h5c;
            8'h4b: xy_out = 8'hcc;
            8'h4c: xy_out = 8'h5d;
            8'h4d: xy_out = 8'h65;
            8'h4e: xy_out = 8'hb6;
            8'h4f: xy_out = 8'h92;
            8'h50: xy_out = 8'h6c;
            8'h51: xy_out = 8'h70;
            8'h52: xy_out = 8'h48;
            8'h53: xy_out = 8'h50;
            8'h54: xy_out = 8'hfd;
            8'h55: xy_out = 8'hed;
            8'h56: xy_out = 8'hb9;
            8'h57: xy_out = 8'hda;
            8'h58: xy_out = 8'h5e;
            8'h59: xy_out = 8'h15;
            8'h5a: xy_out = 8'h46;
            8'h5b: xy_out = 8'h57;
            8'h5c: xy_out = 8'ha7;
            8'h5d: xy_out = 8'h8d;
            8'h5e: xy_out = 8'h9d;
            8'h5f: xy_out = 8'h84;
            8'h60: xy_out = 8'h90;
            8'h61: xy_out = 8'hd8;
            8'h62: xy_out = 8'hab;
            8'h63: xy_out = 8'h00;
            8'h64: xy_out = 8'h8c;
            8'h65: xy_out = 8'hbc;
            8'h66: xy_out = 8'hd3;
            8'h67: xy_out = 8'h0a;
            8'h68: xy_out = 8'hf7;
            8'h69: xy_out = 8'he4;
            8'h6a: xy_out = 8'h58;
            8'h6b: xy_out = 8'h05;
            8'h6c: xy_out = 8'hb8;
            8'h6d: xy_out = 8'hb3;
            8'h6e: xy_out = 8'h45;
            8'h6f: xy_out = 8'h06;
            8'h70: xy_out = 8'hd0;
            8'h71: xy_out = 8'h2c;
            8'h72: xy_out = 8'h1e;
            8'h73: xy_out = 8'h8f;
            8'h74: xy_out = 8'hca;
            8'h75: xy_out = 8'h3f;
            8'h76: xy_out = 8'h0f;
            8'h77: xy_out = 8'h02;
            8'h78: xy_out = 8'hc1;
            8'h79: xy_out = 8'haf;
            8'h7a: xy_out = 8'hbd;
            8'h7b: xy_out = 8'h03;
            8'h7c: xy_out = 8'h01;
            8'h7d: xy_out = 8'h13;
            8'h7e: xy_out = 8'h8a;
            8'h7f: xy_out = 8'h6b;
            8'h80: xy_out = 8'h3a;
            8'h81: xy_out = 8'h91;
            8'h82: xy_out = 8'h11;
            8'h83: xy_out = 8'h41;
            8'h84: xy_out = 8'h4f;
            8'h85: xy_out = 8'h67;
            8'h86: xy_out = 8'hdc;
            8'h87: xy_out = 8'hea;
            8'h88: xy_out = 8'h97;
            8'h89: xy_out = 8'hf2;
            8'h8a: xy_out = 8'hcf;
            8'h8b: xy_out = 8'hce;
            8'h8c: xy_out = 8'hf0;
            8'h8d: xy_out = 8'hb4;
            8'h8e: xy_out = 8'he6;
            8'h8f: xy_out = 8'h73;
            8'h90: xy_out = 8'h96;
            8'h91: xy_out = 8'hac;
            8'h92: xy_out = 8'h74;
            8'h93: xy_out = 8'h22;
            8'h94: xy_out = 8'he7;
            8'h95: xy_out = 8'had;
            8'h96: xy_out = 8'h35;
            8'h97: xy_out = 8'h85;
            8'h98: xy_out = 8'he2;
            8'h99: xy_out = 8'hf9;
            8'h9a: xy_out = 8'h37;
            8'h9b: xy_out = 8'he8;
            8'h9c: xy_out = 8'h1c;
            8'h9d: xy_out = 8'h75;
            8'h9e: xy_out = 8'hdf;
            8'h9f: xy_out = 8'h6e;
            8'ha0: xy_out = 8'h47;
            8'ha1: xy_out = 8'hf1;
            8'ha2: xy_out = 8'h1a;
            8'ha3: xy_out = 8'h71;
            8'ha4: xy_out = 8'h1d;
            8'ha5: xy_out = 8'h29;
            8'ha6: xy_out = 8'hc5;
            8'ha7: xy_out = 8'h89;
            8'ha8: xy_out = 8'h6f;
            8'ha9: xy_out = 8'hb7;
            8'haa: xy_out = 8'h62;
            8'hab: xy_out = 8'h0e;
            8'hac: xy_out = 8'haa;
            8'had: xy_out = 8'h18;
            8'hae: xy_out = 8'hbe;
            8'haf: xy_out = 8'h1b;
            8'hb0: xy_out = 8'hfc;
            8'hb1: xy_out = 8'h56;
            8'hb2: xy_out = 8'h3e;
            8'hb3: xy_out = 8'h4b;
            8'hb4: xy_out = 8'hc6;
            8'hb5: xy_out = 8'hd2;
            8'hb6: xy_out = 8'h79;
            8'hb7: xy_out = 8'h20;
            8'hb8: xy_out = 8'h9a;
            8'hb9: xy_out = 8'hdb;
            8'hba: xy_out = 8'hc0;
            8'hbb: xy_out = 8'hfe;
            8'hbc: xy_out = 8'h78;
            8'hbd: xy_out = 8'hcd;
            8'hbe: xy_out = 8'h5a;
            8'hbf: xy_out = 8'hf4;
            8'hc0: xy_out = 8'h1f;
            8'hc1: xy_out = 8'hdd;
            8'hc2: xy_out = 8'ha8;
            8'hc3: xy_out = 8'h33;
            8'hc4: xy_out = 8'h88;
            8'hc5: xy_out = 8'h07;
            8'hc6: xy_out = 8'hc7;
            8'hc7: xy_out = 8'h31;
            8'hc8: xy_out = 8'hb1;
            8'hc9: xy_out = 8'h12;
            8'hca: xy_out = 8'h10;
            8'hcb: xy_out = 8'h59;
            8'hcc: xy_out = 8'h27;
            8'hcd: xy_out = 8'h80;
            8'hce: xy_out = 8'hec;
            8'hcf: xy_out = 8'h5f;
            8'hd0: xy_out = 8'h60;
            8'hd1: xy_out = 8'h51;
            8'hd2: xy_out = 8'h7f;
            8'hd3: xy_out = 8'ha9;
            8'hd4: xy_out = 8'h19;
            8'hd5: xy_out = 8'hb5;
            8'hd6: xy_out = 8'h4a;
            8'hd7: xy_out = 8'h0d;
            8'hd8: xy_out = 8'h2d;
            8'hd9: xy_out = 8'he5;
            8'hda: xy_out = 8'h7a;
            8'hdb: xy_out = 8'h9f;
            8'hdc: xy_out = 8'h93;
            8'hdd: xy_out = 8'hc9;
            8'hde: xy_out = 8'h9c;
            8'hdf: xy_out = 8'hef;
            8'he0: xy_out = 8'ha0;
            8'he1: xy_out = 8'he0;
            8'he2: xy_out = 8'h3b;
            8'he3: xy_out = 8'h4d;
            8'he4: xy_out = 8'hae;
            8'he5: xy_out = 8'h2a;
            8'he6: xy_out = 8'hf5;
            8'he7: xy_out = 8'hb0;
            8'he8: xy_out = 8'hc8;
            8'he9: xy_out = 8'heb;
            8'hea: xy_out = 8'hbb;
            8'heb: xy_out = 8'h3c;
            8'hec: xy_out = 8'h83;
            8'hed: xy_out = 8'h53;
            8'hee: xy_out = 8'h99;
            8'hef: xy_out = 8'h61;
            8'hf0: xy_out = 8'h17;
            8'hf1: xy_out = 8'h2b;
            8'hf2: xy_out = 8'h04;
            8'hf3: xy_out = 8'h7e;
            8'hf4: xy_out = 8'hba;
            8'hf5: xy_out = 8'h77;
            8'hf6: xy_out = 8'hd6;
            8'hf7: xy_out = 8'h26;
            8'hf8: xy_out = 8'he1;
            8'hf9: xy_out = 8'h69;
            8'hfa: xy_out = 8'h14;
            8'hfb: xy_out = 8'h63;
            8'hfc: xy_out = 8'h55;
            8'hfd: xy_out = 8'h21;
            8'hfe: xy_out = 8'h0c;
            8'hff: xy_out = 8'h7d;
        endcase
    end
endmodule

// ============================================================================
// KeyExpansion - Expansión de clave (versión 32-bit)
// ============================================================================
module KeyExpansion #(parameter Nk = 1, parameter Nr = 5) (
    key_in,
    round_keys
);
localparam Nb = 1;
localparam WORD_SIZE = 32;
localparam BYTE_SIZE = 8;
localparam INPUT_KEY_SIZE = Nk * WORD_SIZE;
localparam NUMBER_OF_GENERATED_WORDS = Nb * (Nr + 1);
localparam ROUND_KEYS_SIZE = WORD_SIZE * NUMBER_OF_GENERATED_WORDS;

input [INPUT_KEY_SIZE - 1 : 0] key_in;
output [ROUND_KEYS_SIZE - 1 : 0] round_keys;

// ----------- Funciones Auxiliares ------------
function [31:0] RotWord(input [31:0] word);
    RotWord = {word[23:0], word[31:24]};
endfunction

function [31:0] SubWord(input [31:0] word);
    begin
        SubWord[31:24] = sB(word[31:24]);
        SubWord[23:16] = sB(word[23:16]);
        SubWord[15:8] = sB(word[15:8]);
        SubWord[7:0] = sB(word[7:0]);
    end
endfunction

function [7:0] sB(input [7:0] word);
    begin
        case (word)
            8'h00: sB = 8'h63; 8'h01: sB = 8'h7c; 8'h02: sB = 8'h77; 8'h03: sB = 8'h7b;
            8'h04: sB = 8'hf2; 8'h05: sB = 8'h6b; 8'h06: sB = 8'h6f; 8'h07: sB = 8'hc5;
            8'h08: sB = 8'h30; 8'h09: sB = 8'h01; 8'h0a: sB = 8'h67; 8'h0b: sB = 8'h2b;
            8'h0c: sB = 8'hfe; 8'h0d: sB = 8'hd7; 8'h0e: sB = 8'hab; 8'h0f: sB = 8'h76;
            8'h10: sB = 8'hca; 8'h11: sB = 8'h82; 8'h12: sB = 8'hc9; 8'h13: sB = 8'h7d;
            8'h14: sB = 8'hfa; 8'h15: sB = 8'h59; 8'h16: sB = 8'h47; 8'h17: sB = 8'hf0;
            8'h18: sB = 8'had; 8'h19: sB = 8'hd4; 8'h1a: sB = 8'ha2; 8'h1b: sB = 8'haf;
            8'h1c: sB = 8'h9c; 8'h1d: sB = 8'ha4; 8'h1e: sB = 8'h72; 8'h1f: sB = 8'hc0;
            8'h20: sB = 8'hb7; 8'h21: sB = 8'hfd; 8'h22: sB = 8'h93; 8'h23: sB = 8'h26;
            8'h24: sB = 8'h36; 8'h25: sB = 8'h3f; 8'h26: sB = 8'hf7; 8'h27: sB = 8'hcc;
            8'h28: sB = 8'h34; 8'h29: sB = 8'ha5; 8'h2a: sB = 8'he5; 8'h2b: sB = 8'hf1;
            8'h2c: sB = 8'h71; 8'h2d: sB = 8'hd8; 8'h2e: sB = 8'h31; 8'h2f: sB = 8'h15;
            8'h30: sB = 8'h04; 8'h31: sB = 8'hc7; 8'h32: sB = 8'h23; 8'h33: sB = 8'hc3;
            8'h34: sB = 8'h18; 8'h35: sB = 8'h96; 8'h36: sB = 8'h05; 8'h37: sB = 8'h9a;
            8'h38: sB = 8'h07; 8'h39: sB = 8'h12; 8'h3a: sB = 8'h80; 8'h3b: sB = 8'he2;
            8'h3c: sB = 8'heb; 8'h3d: sB = 8'h27; 8'h3e: sB = 8'hb2; 8'h3f: sB = 8'h75;
            8'h40: sB = 8'h09; 8'h41: sB = 8'h83; 8'h42: sB = 8'h2c; 8'h43: sB = 8'h1a;
            8'h44: sB = 8'h1b; 8'h45: sB = 8'h6e; 8'h46: sB = 8'h5a; 8'h47: sB = 8'ha0;
            8'h48: sB = 8'h52; 8'h49: sB = 8'h3b; 8'h4a: sB = 8'hd6; 8'h4b: sB = 8'hb3;
            8'h4c: sB = 8'h29; 8'h4d: sB = 8'he3; 8'h4e: sB = 8'h2f; 8'h4f: sB = 8'h84;
            8'h50: sB = 8'h53; 8'h51: sB = 8'hd1; 8'h52: sB = 8'h00; 8'h53: sB = 8'hed;
            8'h54: sB = 8'h20; 8'h55: sB = 8'hfc; 8'h56: sB = 8'hb1; 8'h57: sB = 8'h5b;
            8'h58: sB = 8'h6a; 8'h59: sB = 8'hcb; 8'h5a: sB = 8'hbe; 8'h5b: sB = 8'h39;
            8'h5c: sB = 8'h4a; 8'h5d: sB = 8'h4c; 8'h5e: sB = 8'h58; 8'h5f: sB = 8'hcf;
            8'h60: sB = 8'hd0; 8'h61: sB = 8'hef; 8'h62: sB = 8'haa; 8'h63: sB = 8'hfb;
            8'h64: sB = 8'h43; 8'h65: sB = 8'h4d; 8'h66: sB = 8'h33; 8'h67: sB = 8'h85;
            8'h68: sB = 8'h45; 8'h69: sB = 8'hf9; 8'h6a: sB = 8'h02; 8'h6b: sB = 8'h7f;
            8'h6c: sB = 8'h50; 8'h6d: sB = 8'h3c; 8'h6e: sB = 8'h9f; 8'h6f: sB = 8'ha8;
            8'h70: sB = 8'h51; 8'h71: sB = 8'ha3; 8'h72: sB = 8'h40; 8'h73: sB = 8'h8f;
            8'h74: sB = 8'h92; 8'h75: sB = 8'h9d; 8'h76: sB = 8'h38; 8'h77: sB = 8'hf5;
            8'h78: sB = 8'hbc; 8'h79: sB = 8'hb6; 8'h7a: sB = 8'hda; 8'h7b: sB = 8'h21;
            8'h7c: sB = 8'h10; 8'h7d: sB = 8'hff; 8'h7e: sB = 8'hf3; 8'h7f: sB = 8'hd2;
            8'h80: sB = 8'hcd; 8'h81: sB = 8'h0c; 8'h82: sB = 8'h13; 8'h83: sB = 8'hec;
            8'h84: sB = 8'h5f; 8'h85: sB = 8'h97; 8'h86: sB = 8'h44; 8'h87: sB = 8'h17;
            8'h88: sB = 8'hc4; 8'h89: sB = 8'ha7; 8'h8a: sB = 8'h7e; 8'h8b: sB = 8'h3d;
            8'h8c: sB = 8'h64; 8'h8d: sB = 8'h5d; 8'h8e: sB = 8'h19; 8'h8f: sB = 8'h73;
            8'h90: sB = 8'h60; 8'h91: sB = 8'h81; 8'h92: sB = 8'h4f; 8'h93: sB = 8'hdc;
            8'h94: sB = 8'h22; 8'h95: sB = 8'h2a; 8'h96: sB = 8'h90; 8'h97: sB = 8'h88;
            8'h98: sB = 8'h46; 8'h99: sB = 8'hee; 8'h9a: sB = 8'hb8; 8'h9b: sB = 8'h14;
            8'h9c: sB = 8'hde; 8'h9d: sB = 8'h5e; 8'h9e: sB = 8'h0b; 8'h9f: sB = 8'hdb;
            8'ha0: sB = 8'he0; 8'ha1: sB = 8'h32; 8'ha2: sB = 8'h3a; 8'ha3: sB = 8'h0a;
            8'ha4: sB = 8'h49; 8'ha5: sB = 8'h06; 8'ha6: sB = 8'h24; 8'ha7: sB = 8'h5c;
            8'ha8: sB = 8'hc2; 8'ha9: sB = 8'hd3; 8'haa: sB = 8'hac; 8'hab: sB = 8'h62;
            8'hac: sB = 8'h91; 8'had: sB = 8'h95; 8'hae: sB = 8'he4; 8'haf: sB = 8'h79;
            8'hb0: sB = 8'he7; 8'hb1: sB = 8'hc8; 8'hb2: sB = 8'h37; 8'hb3: sB = 8'h6d;
            8'hb4: sB = 8'h8d; 8'hb5: sB = 8'hd5; 8'hb6: sB = 8'h4e; 8'hb7: sB = 8'ha9;
            8'hb8: sB = 8'h6c; 8'hb9: sB = 8'h56; 8'hba: sB = 8'hf4; 8'hbb: sB = 8'hea;
            8'hbc: sB = 8'h65; 8'hbd: sB = 8'h7a; 8'hbe: sB = 8'hae; 8'hbf: sB = 8'h08;
            8'hc0: sB = 8'hba; 8'hc1: sB = 8'h78; 8'hc2: sB = 8'h25; 8'hc3: sB = 8'h2e;
            8'hc4: sB = 8'h1c; 8'hc5: sB = 8'ha6; 8'hc6: sB = 8'hb4; 8'hc7: sB = 8'hc6;
            8'hc8: sB = 8'he8; 8'hc9: sB = 8'hdd; 8'hca: sB = 8'h74; 8'hcb: sB = 8'h1f;
            8'hcc: sB = 8'h4b; 8'hcd: sB = 8'hbd; 8'hce: sB = 8'h8b; 8'hcf: sB = 8'h8a;
            8'hd0: sB = 8'h70; 8'hd1: sB = 8'h3e; 8'hd2: sB = 8'hb5; 8'hd3: sB = 8'h66;
            8'hd4: sB = 8'h48; 8'hd5: sB = 8'h03; 8'hd6: sB = 8'hf6; 8'hd7: sB = 8'h0e;
            8'hd8: sB = 8'h61; 8'hd9: sB = 8'h35; 8'hda: sB = 8'h57; 8'hdb: sB = 8'hb9;
            8'hdc: sB = 8'h86; 8'hdd: sB = 8'hc1; 8'hde: sB = 8'h1d; 8'hdf: sB = 8'h9e;
            8'he0: sB = 8'he1; 8'he1: sB = 8'hf8; 8'he2: sB = 8'h98; 8'he3: sB = 8'h11;
            8'he4: sB = 8'h69; 8'he5: sB = 8'hd9; 8'he6: sB = 8'h8e; 8'he7: sB = 8'h94;
            8'he8: sB = 8'h9b; 8'he9: sB = 8'h1e; 8'hea: sB = 8'h87; 8'heb: sB = 8'he9;
            8'hec: sB = 8'hce; 8'hed: sB = 8'h55; 8'hee: sB = 8'h28; 8'hef: sB = 8'hdf;
            8'hf0: sB = 8'h8c; 8'hf1: sB = 8'ha1; 8'hf2: sB = 8'h89; 8'hf3: sB = 8'h0d;
            8'hf4: sB = 8'hbf; 8'hf5: sB = 8'he6; 8'hf6: sB = 8'h42; 8'hf7: sB = 8'h68;
            8'hf8: sB = 8'h41; 8'hf9: sB = 8'h99; 8'hfa: sB = 8'h2d; 8'hfb: sB = 8'h0f;
            8'hfc: sB = 8'hb0; 8'hfd: sB = 8'h54; 8'hfe: sB = 8'hbb; 8'hff: sB = 8'h16;
        endcase
    end
endfunction

function [31:0] Rcon(input [3:0]i);
    begin
        case(i) 
            4'h1 : Rcon = 32'h01000000;
            4'h2 : Rcon = 32'h02000000;
            4'h3 : Rcon = 32'h04000000;
            4'h4 : Rcon = 32'h08000000;
            4'h5 : Rcon = 32'h10000000;
            4'h6 : Rcon = 32'h20000000;
            4'h7 : Rcon = 32'h40000000;
            4'h8 : Rcon = 32'h80000000;
            4'h9 : Rcon = 32'h1b000000;
            4'hA : Rcon = 32'h36000000;
            default : Rcon = 32'h00000000;
        endcase
    end
endfunction

// ----------- Expansión de Clave para 32 bits ------------
// La primera palabra es la clave original
assign round_keys[ROUND_KEYS_SIZE - 1 : ROUND_KEYS_SIZE - INPUT_KEY_SIZE] = key_in;

genvar i;
generate    
    begin
        for(i = Nk; i < NUMBER_OF_GENERATED_WORDS; i = i + 1) begin : key_expansion
            wire [WORD_SIZE - 1 : 0] temp1, temp2;
            assign temp1 = round_keys[ROUND_KEYS_SIZE - (i - 1) * WORD_SIZE - 1 -: WORD_SIZE];
            
            // Para Nk=1, cada palabra necesita transformación
            if(i % Nk == 0) begin
                assign temp2 = SubWord(RotWord(temp1)) ^ Rcon(i / Nk);
            end
            else begin
                assign temp2 = temp1;
            end
            
            assign round_keys[ROUND_KEYS_SIZE - i * WORD_SIZE - 1 -: WORD_SIZE] = 
                round_keys[ROUND_KEYS_SIZE - (i - Nk) * WORD_SIZE - 1 -: WORD_SIZE] ^ temp2;
        end
    end
endgenerate
endmodule
