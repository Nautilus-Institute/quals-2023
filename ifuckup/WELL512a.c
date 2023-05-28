/* ***************************************************************************** */
/* Copyright:      Francois Panneton and Pierre L'Ecuyer, University of Montreal */
/*                 Makoto Matsumoto, Hiroshima University                        */
/* Notice:         This code can be used freely for personal, academic,          */
/*                 or non-commercial purposes. For commercial purposes,          */
/*                 please contact P. L'Ecuyer at: lecuyer@iro.UMontreal.ca       */
/* ***************************************************************************** */
#include "ifuckup.h"

#define M1 13
#define M2 9

#define MAT0POS(t,v) (v^(v>>t))
#define MAT0NEG(t,v) (v^(v<<(-(t))))
#define MAT3NEG(t,v) (v<<(-(t)))
#define MAT4NEG(t,b,v) (v ^ ((v<<(-(t))) & b))

#define V0            ctx->STATE[ctx->state_i                   ]
#define VM1           ctx->STATE[(ctx->state_i+M1) & 0x0000000fU]
#define VM2           ctx->STATE[(ctx->state_i+M2) & 0x0000000fU]
#define VRm1          ctx->STATE[(ctx->state_i+15) & 0x0000000fU]
#define newV0         ctx->STATE[(ctx->state_i+15) & 0x0000000fU]
#define newV1         ctx->STATE[ctx->state_i                   ] 

#define FACT 2.32830643653869628906e-10

void InitWELLRNG512a (WELLStruct *ctx){
   ctx->state_i = 0;
   f_getrandom(ctx->STATE, sizeof(ctx->STATE), 0);
}

double WELLRNG512a (WELLStruct *ctx){
  unsigned int z0, z1, z2;
  z0    = VRm1;
  z1    = MAT0NEG (-16,V0)    ^ MAT0NEG (-15, VM1);
  z2    = MAT0POS (11, VM2)  ;
  newV1 = z1                  ^ z2; 
  newV0 = MAT0NEG (-2,z0)     ^ MAT0NEG(-18,z1)    ^ MAT3NEG(-28,z2) ^ MAT4NEG(-5,0xda442d24U,newV1) ;
  ctx->state_i = (ctx->state_i + 15) & 0x0000000fU;
  //printf("STATE[%d]: %08x\n", ctx->state_i, STATE[ctx->state_i]);
  return ((double) ctx->STATE[ctx->state_i]) * FACT;
}

/*
void PrintWELL(WELLStruct *ctx)
{
	int i, x;
  unsigned int Val;
  char Buffer[9];

	for(i = 0; i < R; i++)
	{
		if((i != 0) && (i%4) == 0)
			send_string("\n");

    send_string("STATE[");

    //%02d
    Buffer[0] = 0x30 + (i / 10);
    Buffer[1] = 0x30 + (i % 10);
    Buffer[2] = 0;
    send_string(Buffer);

    send_string(": ");

    //%08x
    ConvertValToHex(ctx->STATE[i], Buffer);
    Buffer[8] = 0;
    send_string(Buffer);
    send_string("\t");
	}
	send_string("\n");

}
*/