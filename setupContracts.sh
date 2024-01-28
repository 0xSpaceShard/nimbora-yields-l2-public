#! /bin/bash

echo Setup pooling manager
npx ts-node scripts/setupPoolingManager.ts
echo

echo Deploy Strategy
npx ts-node scripts/deploySdaiStrategy.ts
echo


