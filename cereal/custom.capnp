using Cxx = import "./include/c++.capnp";
$Cxx.namespace("cereal");

@0xb526ba661d550a59;

# custom.capnp: a home for empty structs reserved for custom forks
# These structs are guaranteed to remain reserved and empty in mainline
# cereal, so use these if you want custom events in your fork.

# DO rename the structs
# DON'T change the identifier (e.g. @0x81c2f05a394cf4af)

struct TeslaCommand @0x81c2f05a394cf4af {
  command @0 :Text;
  arg @1 :Text;
}

struct TeslaState @0xaedffd8f31e7b55d {
  connected @0 :Bool;
  whitelisted @1 :Bool;
  infotainmentReady @2 :Bool;
  lastEvent @3 :Text;
  car @4 :TeslaCarState;
}

struct TeslaCarState @0xf35cc4560bbf6ec2 {
  # ─── VCSEC VehicleStatus (unsolicited broadcasts from the car) ───
  # lockState:    0=unlocked, 1=locked, 2=internal_locked, 3=selective_unlocked
  # sleepStatus:  0=unknown, 1=awake, 2=asleep
  # userPresence: 0=unknown, 1=not_present, 2=present
  lockState @0 :UInt32;
  sleepStatus @1 :UInt32;
  userPresence @2 :UInt32;
  # Closure state (from ClosureState_E):
  # 0=closed, 1=open, 2=ajar, 3=unknown, 4=failed_unlatch, 5=opening, 6=closing
  frontDriverDoor @3 :UInt32;
  frontPassengerDoor @4 :UInt32;
  rearDriverDoor @5 :UInt32;
  rearPassengerDoor @6 :UInt32;
  rearTrunk @7 :UInt32;
  frontTrunk @8 :UInt32;
  chargePort @9 :UInt32;
  tonneau @10 :UInt32;

  # ─── Infotainment data (populated by GetVehicleData queries) ───
  # Charge
  chargePercent @11 :Float32;
  batteryRangeMiles @12 :Float32;
  chargingState @13 :Text;
  chargeLimitSoc @14 :UInt32;
  chargerPower @15 :Float32;
  # Climate
  insideTempC @16 :Float32;
  outsideTempC @17 :Float32;
  hvacOn @18 :Bool;
  driverTempSetpointC @19 :Float32;
  passengerTempSetpointC @20 :Float32;
  # Drive
  speedMph @21 :Float32;
  gear @22 :Text;
  heading @23 :Float32;
  # Location
  latitude @24 :Float64;
  longitude @25 :Float64;
  # Odometer
  odometerMiles @26 :Float32;
  # Media
  mediaPlaying @27 :Bool;
  mediaTrack @28 :Text;
  mediaArtist @29 :Text;
  # Last update timestamps (monotonic seconds since teslad start, or 0 if never)
  vcsecUpdatedAt @30 :Float64;
  infotainmentUpdatedAt @31 :Float64;
}

struct CustomReserved3 @0xda96579883444c35 {
}

struct CustomReserved4 @0x80ae746ee2596b11 {
}

struct CustomReserved5 @0xa5cd762cd951a455 {
}

struct CustomReserved6 @0xf98d843bfd7004a3 {
}

struct CustomReserved7 @0xb86e6369214c01c8 {
}

struct CustomReserved8 @0xf416ec09499d9d19 {
}

struct CustomReserved9 @0xa1680744031fdb2d {
}

struct CustomReserved10 @0xcb9fd56c7057593a {
}

struct CustomReserved11 @0xc2243c65e0340384 {
}

struct CustomReserved12 @0x9ccdc8676701b412 {
}

struct CustomReserved13 @0xcd96dafb67a082d0 {
}

struct CustomReserved14 @0xb057204d7deadf3f {
}

struct CustomReserved15 @0xbd443b539493bc68 {
}

struct CustomReserved16 @0xfc6241ed8877b611 {
}

struct CustomReserved17 @0xa30662f84033036c {
}

struct CustomReserved18 @0xc86a3d38d13eb3ef {
}

struct CustomReserved19 @0xa4f1eb3323f5f582 {
}
