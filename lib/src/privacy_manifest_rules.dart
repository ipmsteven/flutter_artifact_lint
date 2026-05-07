// Based on Apple's "NSPrivacyAccessedAPIType" documentation, checked on
// 2026-05-07. Apple states this list may change over time.
const requiredReasonCodesByCategory = {
  'NSPrivacyAccessedAPICategoryFileTimestamp': {
    'DDA9.1',
    'C617.1',
    '3B52.1',
    '0A2A.1',
  },
  'NSPrivacyAccessedAPICategorySystemBootTime': {'35F9.1', '8FFB.1', '3D61.1'},
  'NSPrivacyAccessedAPICategoryDiskSpace': {
    '85F4.1',
    'E174.1',
    '7D9E.1',
    'B728.1',
  },
  'NSPrivacyAccessedAPICategoryActiveKeyboards': {'3EC4.1', '54BD.1'},
  'NSPrivacyAccessedAPICategoryUserDefaults': {
    'CA92.1',
    '1C8F.1',
    'C56D.1',
    'AC6B.1',
  },
};
