fd :: FromDump("f7a.dump", TIMING true, STOP true);
shaper0 :: BandwidthShaper(384kbps);
shaper1 :: BandwidthShaper(96kbps);
shaper2 :: BandwidthShaper(430kbps);
ipclass :: IPClassifier(tcp, -);
td :: ToDump("f7b.dump", ENCAP IP);
queue0 :: ThreadSafeQueue(6000);
queue1 :: ThreadSafeQueue(6000);
queue2 :: Unqueue;
queue3 :: Unqueue;
queue4 :: Unqueue;

//PollDevice
fd -> SetTimestamp -> shaper2 -> queue2 -> ipclass[0, 1] => queue0, queue1 => shaper0, shaper1 => queue3, queue4 -> td;
