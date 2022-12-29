static const long long COIN = 100000000;

static const long long nDiffChangeTarget = 67200; // Patch effective @ block 67200
static const long long patchBlockRewardDuration = 10080; // 10080 blocks main net change
static const long long patchBlockRewardDuration2 = 80160; // 80160 blocks main net change
static const long long patchBlockRewardDuration3 = 400000; // block 400000 after which all difficulties are updated on every block

double ConvertBitsToDouble(unsigned int nBits)
{
    int nShift = (nBits >> 24) & 0xff;

    double dDiff =
        (double)0x0000ffff / (double)(nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

long long GetDGBSubsidy(int nHeight) {
        long long qSubsidy;

        if (nHeight < patchBlockRewardDuration3)
        {
                long long qSubsidy = 8000*COIN;
                int blocks = nHeight - nDiffChangeTarget;
                int weeks = (blocks / patchBlockRewardDuration)+1;
                //decrease reward by 0.5% every 10080 blocks
                for(int i = 0; i < weeks; i++)  qSubsidy -= (qSubsidy/200);
        }
        else
        {
                long long qSubsidy = 2459*COIN;
                int blocks = nHeight - patchBlockRewardDuration3;
                int weeks = (blocks / patchBlockRewardDuration2)+1;
                //decrease reward by 1% every month
                for(int i = 0; i < weeks; i++)  qSubsidy -= (qSubsidy/100);
        }
        return qSubsidy;
}

long long static GetBlockBaseValue(int nHeight) {

   long long nSubsidy = COIN;

   if(nHeight < nDiffChangeTarget) {
      //this is pre-patch, reward is 8000.
      nSubsidy = 8000 * COIN;
      if(nHeight < 1440)  //1440
      {
        nSubsidy = 72000 * COIN;
      }
      else if(nHeight < 5760)  //5760
      {
        nSubsidy = 16000 * COIN;
      }

   } else {
      //patch takes effect after 67,200 blocks solved
      nSubsidy = GetDGBSubsidy(nHeight);
   }

   //make sure the reward is at least 1 DGB
   if(nSubsidy < COIN) {
      nSubsidy = COIN;
   }

   return nSubsidy;
}