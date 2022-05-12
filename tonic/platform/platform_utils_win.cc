// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "platform_utils.h"

#include <windows.h>

namespace tonic {

void PlatformExit(int status) {
  ::ExitProcess(status);
}

}  // namespace tonic
