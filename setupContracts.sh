#! /bin/bash

echo Deploy Strategy
npx ts-node scripts/deploySdaiStrategy.ts
echo

echo Setup pooling manager
npx ts-node scripts/setupPoolingManager.ts
echo

