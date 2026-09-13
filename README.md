Cabana native Signals docking review media

Code: greatgitsby/openpilot, t3code/fix-cabana-tab-padding at 3626b86cc.

Before: original application capture at 4c0799eb8, prior to the padding and native Signals docking changes. After: 3626b86cc. Same 1600×900 viewport, light theme, local demo route, Ford DBC, WheelSpeed/SteeringPinion_Data tabs, and playback paused around 13 seconds. Video output disabled.

- comparison.gif: labeled before/after.
- before.gif and after.gif: message tab switching.
- docking-test.gif: actual screen recording of docking Charts into Signals, switching dock tabs, undocking Signals, and redocking it.

Validation: Cabana SCons build passed. Scripted Xvfb tests confirmed saved shared layouts retain both panels and reveal their tabs, Charts docks into Signals, Signals undocks and redocks, and the final saved dock IDs match.

Media only; this branch is separate from the code PR.
