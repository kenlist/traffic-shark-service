enum ReturnCode {
    OK = 0,
    #INVALID_IP,
    #INVALID_TIMEOUT,
    #ID_EXHAUST,
    #NETLINK_ERROR,
    #UNKNOWN_ERROR,
    #NETLINK_HTB_ERROR,
    #UNKNOWN_HTB_ERROR,
    #NETLINK_NETEM_ERROR,
    #UNKNOWN_NETEM_ERROR,
    #NETLINK_FW_ERROR,
    #UNKNOWN_FW_ERROR,
    #UNKNOWN_SESSION,
    #UNKNOWN_IP,
    #ACCESS_DENIED,
}

struct Delay {
  1: i32 delay,
  2: optional i32 jitter = 0,
  3: optional double correlation = 0,
}

struct Loss {
  1: double percentage,
  2: optional double correlation = 0,
}

struct Reorder {
  1: double percentage,
  2: i32 gap = 0,
  3: optional double correlation = 0,
}

struct Corruption {
  1: double percentage = 0,
  2: optional double correlation = 0,
}

struct Shaping {
  1: i32 rate,
  2: optional Delay delay = {"delay": 0},
  3: optional Loss loss = {"percentage": 0},
  4: optional Reorder reorder = {"percentage": 0},
  5: optional Corruption corruption = {"percentage": 0},
  6: optional list<string> iptables_options,
}

struct TrafficControlSetting {
  1: Shaping up,
  2: Shaping down,
}

struct TrafficControlRc {
  1: ReturnCode code,
  2: optional string message,
}

exception TrafficControlException {
  1: ReturnCode code,
  2: optional string message,
}

struct MachineControlState {
  1: string ip,
  2: string profile_name,
  3: bool is_shaping,
  4: bool online,
  5: i64 last_update_time,
}

struct MachineControl {
  1: string mac,
  2: MachineControlState state,
}

struct Profile {
  1: string name,
  2: TrafficControlSetting tc_setting,
}

service TrafficSharkService {
  /* machine control api */
  list<MachineControl> getMachineControls()
    throws (1: TrafficControlException failure),
  TrafficControlRc updateMachineControl(1: MachineControl mc)
    throws (1: TrafficControlException failure),
  TrafficControlRc shapeMachine(1: string mac)
    throws (1: TrafficControlException failure),
  TrafficControlRc unshapeMachine(1: string mac)
    throws (1: TrafficControlException failure),

  /* profiles relative api */
  list<Profile> getProfiles(),
  TrafficControlRc addProfile(1: Profile profile)
    throws (1: TrafficControlException failure),
  TrafficControlRc removeProfile(1: string name)
    throws (1: TrafficControlException failure),
}