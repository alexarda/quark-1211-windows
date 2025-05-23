/*++

  Copyright (c) 2013-2016 Intel Corporation.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

  * Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.
  * Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in
  the documentation and/or other materials provided with the
  distribution.
  * Neither the name of Intel Corporation nor the names of its
  contributors may be used to endorse or promote products derived
  from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

  Module Name:

    Cpu0Cst.ASL

  Abstract:

    CPU C State control methods

--*/

DefinitionBlock (
    "Cpu0Cst.aml",
    "SSDT",
    0x01,
    "SsgPmm",
    "Cpu0Cst",
    0x0011
    )
{
    External(\_PR.CPU0, DeviceObj)
    External (PDC0, IntObj)
    External (CFGD, FieldUnitObj)

    Scope(\_PR.CPU0)
    {
        Method (_CST, 0)
        {
            // If CMP is supported, and OSPM is not capable of independent C1, P, T state
            // support for each processor for multi-processor configuration, we will just report
            // C1 halt 
            //
            // PDCx[4] = Indicates whether OSPM is not capable of independent C1, P, T state
            // support for each processor for multi-processor configuration.
            //
            If(LAnd(And(CFGD,0x01000000), LNot(And(PDC0,0x10))))
            {
              Return(Package() {
                1,
                Package()
                { // C1 halt
                  ResourceTemplate(){Register(FFixedHW, 0, 0, 0)},
                  1,
                  157,
                  1000
                }
              })
            }

            //
            // If MWAIT extensions is supported and OSPM is capable of performing
            // native C state instructions for the C2/C3 in multi-processor configuration,
            // we report every c state with MWAIT extensions.
            //
            // PDCx[9] = Indicates whether OSPM is capable of performing native C state instructions
            // for the C2/C3 in multi-processor configuration
            //
            If(LAnd(And(CFGD, 0x200000), And(PDC0,0x200)))
            {
              //
              // If C6 is supported, we report MWAIT C1,C2,C4,C6
              //
              If(And(CFGD,0x200))
              {
                Return( Package()
                {
                  4,
                  Package()
                  { // MWAIT C1, hardware coordinated with no bus master avoidance
                    ResourceTemplate(){Register(FFixedHW, 1, 2, 0x00, 1)},
                    1,
                    1,
                    1000
                  },
                  Package()
                  { // MWAIT C2, hardware coordinated with no bus master avoidance
                    ResourceTemplate(){Register(FFixedHW, 1, 2, 0x10, 1)},
                    2,
                    20,
                    500
                  },
                  Package()
                  { // MWAIT C4, hardware coordinated with bus master avoidance enabled
                    ResourceTemplate(){Register(FFixedHW, 1, 2, 0x30, 3)},
                    3,
                    100,
                    100
                  },
                  Package()
                  { // MWAIT C6, hardware coordinated with bus master avoidance enabled
                    ResourceTemplate(){Register(FFixedHW, 1, 2, 0x50, 3)},
                    3,
                    140,
                    10
                  }
                })
              }
              //
              // If C4 is supported, we report MWAIT C1,C2,C4
              //
              If(And(CFGD,0x080))
              {
                Return( Package()
                {
                  3,
                  Package()
                  { // MWAIT C1, hardware coordinated with no bus master avoidance
                    ResourceTemplate(){Register(FFixedHW, 1, 2, 0x00, 1)},
                    1,
                    1,
                    1000
                  },
                  Package()
                  { // MWAIT C2, hardware coordinated with no bus master avoidance
                    ResourceTemplate(){Register(FFixedHW, 1, 2, 0x10, 1)},
                    2,
                    20,
                    500
                  },
                  Package()
                  { // MWAIT C4, hardware coordinated with bus master avoidance enabled
                    ResourceTemplate(){Register(FFixedHW, 1, 2, 0x30, 3)},
                    3,
                    100,
                    100
                  }
                })
              }
              //
              // If C2 is supported, we report MWAIT C1,C2
              //
              If(And(CFGD,0x020))
              {
                Return( Package()
                {
                  2,
                  Package()
                  { // MWAIT C1, hardware coordinated with no bus master avoidance
                    ResourceTemplate(){Register(FFixedHW, 1, 2, 0x00, 1)},
                    1,
                    1,
                    1000
                  },
                  Package()
                  { // MWAIT C2, hardware coordinated with no bus master avoidance
                    ResourceTemplate(){Register(FFixedHW, 1, 2, 0x10, 1)},
                    2,
                    20,
                    500
                  }
                })
              }
              //
              // Else we only report MWAIT C1.
              //
              Return(Package()
              {
                1,
                Package()
                { // MWAIT C1, hardware coordinated with no bus master avoidance
                  ResourceTemplate () {Register(FFixedHW, 1, 2, 0x00, 1)},
                  1,
                  1,
                  1000
                }
              })
            }

            // If OSPM is only capable of performing native C state instructions for
            // the C1 in multi-processor configuration, we report C1 with MWAIT, other
            // C states with IO method.
            //
            // PDCx[8] = Indicates whether OSPM is capable of performing native C state instructions
            // for the C1 in multi-processor configuration
            //
            If(LAnd(And(CFGD, 0x200000), And(PDC0,0x100)))
            {
              //
              // If C6 is supported, we report MWAIT C1, IO C2,C4,C6
              //
              If(And(CFGD,0x200))
              {
                Return( Package()
                {
                  4,
                  Package()
                  { // MWAIT C1, hardware coordinated with no bus master avoidance
                    ResourceTemplate () {Register(FFixedHW, 1, 2, 0x00, 1)},
                    1,
                    1,
                    1000
                  },
                  Package()
                  { // IO C2 ("PMBALVL2" will be updated at runtime)
                    ResourceTemplate () {Register(SystemIO, 8, 0, 0x324C564C41424D50)},
                    2,
                    20,
                    500
                    },
                  Package()
                  { // IO C4 ("PMBALVL4" will be updated at runtime)
                    ResourceTemplate () {Register(SystemIO, 8, 0, 0x344C564C41424D50)},
                    3,
                    100,
                    100
                  },
                  Package()
                  { // IO C6 ("PMBALVL6" will be updated at runtime)
                    ResourceTemplate () {Register(SystemIO, 8, 0, 0x364C564C41424D50)},
                    3,
                    140,
                    10
                  }
                })
              }
              //
              // If C4 is supported, we report MWAIT C1, IO C2,C4
              //
              If(And(CFGD,0x080))
              {
                Return( Package()
                {
                  3,
                  Package()
                  { // MWAIT C1, hardware coordinated with no bus master avoidance
                    ResourceTemplate () {Register(FFixedHW, 1, 2, 0x00, 1)},
                    1,
                    1,
                    1000
                  },
                  Package()
                  { // IO C2 ("PMBALVL2" will be updated at runtime)
                    ResourceTemplate () {Register(SystemIO, 8, 0, 0x324C564C41424D50)},
                    2,
                    20,
                    500
                    },
                  Package()
                  { // IO C4 ("PMBALVL4" will be updated at runtime)
                    ResourceTemplate () {Register(SystemIO, 8, 0, 0x344C564C41424D50)},
                    3,
                    100,
                    100
                  }
                })
              }
              //
              // If C2 is supported, we report MWAIT C1, IO C2
              //
              If(And(CFGD,0x020))
              {
                Return( Package()
                {
                  2,
                  Package()
                  { // MWAIT C1, hardware coordinated with no bus master avoidance
                    ResourceTemplate () {Register(FFixedHW, 1, 2, 0x00, 1)},
                    1,
                    1,
                    1000
                  },
                  Package()
                  { // IO C2 ("PMBALVL2" will be updated at runtime)
                    ResourceTemplate () {Register(SystemIO, 8, 0, 0x324C564C41424D50)},
                    2,
                    20,
                    500
                  }
                })
              }
              //
              // Else we only report MWAIT C1.
              //
              Return(Package()
              {
                1,
                Package()
                { // MWAIT C1, hardware coordinated with no bus master avoidance
                  ResourceTemplate () {Register(FFixedHW, 1, 2, 0x00, 1)},
                  1,
                  1,
                  1000
                }
              })
            }

            //
            // If MWAIT is not supported, we report all the c states with IO method
            //

            //
            // If C6 is supported, we report C1 halt, IO C2,C4,C6
            //
            If(And(CFGD,0x200))
            {
              Return(Package()
              {
                4,
                Package()
                { // C1 Halt
                  ResourceTemplate () {Register(FFixedHW, 0, 0, 0)},
                  1,
                  1,
                  1000
                },
                Package()
                { // IO C2 ("PMBALVL2" will be updated at runtime)
                  ResourceTemplate () {Register(SystemIO, 8, 0, 0x324C564C41424D50)},
                  2,
                  20,
                  500
                },
                Package()
                { // IO C4 ("PMBALVL4" will be updated at runtime)
                  ResourceTemplate () {Register(SystemIO, 8, 0, 0x344C564C41424D50)},
                  3,
                  100,
                  100
                },
                Package()
                { // IO C6 ("PMBALVL6" will be updated at runtime)
                  ResourceTemplate () {Register(SystemIO, 8, 0, 0x364C564C41424D50)},
                  3,
                  140,
                  10
                }
              })
            }
            //
            // If C4 is supported, we report C1 halt, IO C2,C4
            //
            If(And(CFGD,0x080))
            {
              Return(Package()
              {
                3,
                Package()
                { // C1 halt
                  ResourceTemplate () {Register(FFixedHW, 0, 0, 0)},
                  1,
                  1,
                  1000
                },
                Package()
                { // IO C2 ("PMBALVL2" will be updated at runtime)
                  ResourceTemplate () {Register(SystemIO, 8, 0, 0x324C564C41424D50)},
                  2,
                  20,
                  500
                },
                Package()
                { // IO C4 ("PMBALVL4" will be updated at runtime)
                  ResourceTemplate () {Register(SystemIO, 8, 0, 0x344C564C41424D50)},
                  3,
                  100,
                  100
                }
              })
            }

            //
            // If C2 is supported, we report C1 halt, IO C2
            //
            If(And(CFGD,0x020))
            {
              Return(Package()
              {
                2,
                Package()
                { // C1 halt
                  ResourceTemplate () {Register(FFixedHW, 0, 0, 0)},
                  1,
                  1,
                  1000
                },
                Package()
                { // IO C2 ("PMBALVL2" will be updated at runtime)
                  ResourceTemplate () {Register(SystemIO, 8, 0, 0x324C564C41424D50)},
                  2,
                  20,
                  500
                }
              })
            }
            //
            // Else we only report C1 halt.
            //
            Return(Package()
            {
              1,
              Package()
              { // C1 halt
                ResourceTemplate () {Register(FFixedHW, 0, 0, 0)},
                1,
                1,
                1000
              }
            })
        }
    }
}
