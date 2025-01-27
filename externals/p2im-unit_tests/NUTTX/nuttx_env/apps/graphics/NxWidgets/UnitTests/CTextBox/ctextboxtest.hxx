/////////////////////////////////////////////////////////////////////////////
// apps/graphics/NxWidgets/UnitTests/CTextBox/ctextboxtest.hxx
//
//   Copyright (C) 2012 Gregory Nutt. All rights reserved.
//   Author: Gregory Nutt <gnutt@nuttx.org>
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
// 3. Neither the name NuttX, NxWidgets, nor the names of its contributors
//    me be used to endorse or promote products derived from this software
//    without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
// OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
// AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
// ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
//////////////////////////////////////////////////////////////////////////////

#ifndef __UNITTESTS_CTEXTBOX_CTEXTBOXTEST_HXX
#define __UNITTESTS_CTEXTBOX_CTEXTBOXTEST_HXX

/////////////////////////////////////////////////////////////////////////////
// Included Files
/////////////////////////////////////////////////////////////////////////////

#include <nuttx/config.h>

#include <nuttx/init.h>
#include <cstdio>
#include <semaphore.h>
#include <debug.h>

#include <nuttx/nx/nx.h>

#include "nxconfig.hxx"
#include "cwidgetcontrol.hxx"
#include "ccallback.hxx"
#include "cbgwindow.hxx"
#include "cnxserver.hxx"
#include "cnxfont.hxx"
#include "cnxstring.hxx"
#include "ctextbox.hxx"

/////////////////////////////////////////////////////////////////////////////
// Definitions
/////////////////////////////////////////////////////////////////////////////
// Configuration ////////////////////////////////////////////////////////////

#ifndef CONFIG_HAVE_CXX
#  error "CONFIG_HAVE_CXX must be defined"
#endif

#ifndef CONFIG_CTEXTBOXTEST_BGCOLOR
#  define CONFIG_CTEXTBOXTEST_BGCOLOR CONFIG_NXWIDGETS_DEFAULT_BACKGROUNDCOLOR
#endif

#ifndef CONFIG_CTEXTBOXTEST_FONTCOLOR
#  define CONFIG_CTEXTBOXTEST_FONTCOLOR CONFIG_NXWIDGETS_DEFAULT_FONTCOLOR
#endif

/////////////////////////////////////////////////////////////////////////////
// Public Classes
/////////////////////////////////////////////////////////////////////////////

using namespace NXWidgets;

class CTextBoxTest : public CNxServer
{
private:
  CWidgetControl    *m_widgetControl;  // The controlling widget for the window
  CNxFont           *m_nxFont;         // Default font
  CBgWindow         *m_bgWindow;       // Background window instance
  CNxString         *m_text;           // The label string

public:
  // Constructor/destructors

  CTextBoxTest();
  ~CTextBoxTest();

  // Initializer/unitializer.  These methods encapsulate the basic steps for
  // starting and stopping the NX server

  bool connect(void);
  void disconnect(void);

  // Create a window.  This method provides the general operations for
  // creating a window that you can draw within.
  //
  // Those general operations are:
  // 1) Create a dumb CWigetControl instance
  // 2) Pass the dumb CWidgetControl instance to the window constructor
  //    that inherits from INxWindow.  This will "smarten" the CWidgetControl
  //    instance with some window knowlede
  // 3) Call the open() method on the window to display the window.
  // 4) After that, the fully smartened CWidgetControl instance can
  //    be used to generate additional widgets by passing it to the
  //    widget constructor

  bool createWindow(void);

  // Create a CTextBox instance.  This method will show you how to create
  // a CTextBox widget

  CTextBox *createTextBox(void);

  // Draw the label.  This method illustrates how to draw the CTextBox widget.

  void showTextBox(CTextBox *label);

  // Inject simulated keyboard characters into NX.

  void injectChars(CTextBox *textbox, int nCh, FAR const uint8_t *string);
};

/////////////////////////////////////////////////////////////////////////////
// Public Data
/////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////
// Public Function Prototypes
/////////////////////////////////////////////////////////////////////////////


#endif // __UNITTESTS_CTEXTBOX_CTEXTBOXTEST_HXX
