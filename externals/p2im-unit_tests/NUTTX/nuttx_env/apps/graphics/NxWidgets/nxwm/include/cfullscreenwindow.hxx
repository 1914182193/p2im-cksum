/****************************************************************************
 * apps/graphics/NxWidgets/nxwm/include/cfullscreenwindow.hxx
 *
 *   Copyright (C) 2012 Gregory Nutt. All rights reserved.
 *   Author: Gregory Nutt <gnutt@nuttx.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name NuttX, NxWidgets, nor the names of its contributors
 *    me be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

#ifndef __APPS_GRAPHICS_NXWM_INCLUDECFULLSCREENWINDOW_NXX
#define __APPS_GRAPHICS_NXWM_INCLUDECFULLSCREENWINDOW_NXX

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include "cnxwindow.hxx"
#include "cwidgetcontrol.hxx"

#include "iapplicationwindow.hxx"

/****************************************************************************
 * Pre-Processor Definitions
 ****************************************************************************/

/****************************************************************************
 * Implementation Classes
 ****************************************************************************/

#if defined(__cplusplus)

namespace NxWM
{
  /**
   * This class represents a generic window.  This bland window is used,
   * for example, to support full screen displays.
   */

  class CFullScreenWindow : public IApplicationWindow
  {
  protected:
    NXWidgets::CNxWindow *m_window; /**< The generic window used by the application */

  public:

    /**
     * CFullScreenWindow Constructor
     *
     * @param window.  The raw window to be used by this full screen application.
     */

    CFullScreenWindow(NXWidgets::CNxWindow *window);

    /**
     * CFullScreenWindow Destructor
     */

    ~CFullScreenWindow(void);

    /**
     * Initialize window.  Window initialization is separate from
     * object instantiation so that failures can be reported.
     *
     * @return True if the window was successfully initialized.
     */

    bool open(void);

    /**
     * Re-draw the application window
     */

    void redraw(void);

    /**
     * The application window is hidden (either it is minimized or it is
     * maximized, but not at the top of the hierarchy)
     */

    void hide(void);

    /**
     * Recover the contained NXTK window instance
     *
     * @return.  The window used by this application
     */

    NXWidgets::INxWindow *getWindow(void) const;

    /**
     * Recover the contained widget control
     *
     * @return.  The widget control used by this application
     */

    NXWidgets::CWidgetControl *getWidgetControl(void) const;

    /**
     * Block further activity on this window in preparation for window
     * shutdown.
     *
     * @param app. The application to be blocked
     */

    void block(IApplication *app);

    /**
     * Set the window label
     *
     * @param appname.  The name of the application to place on the window
     */

    void setWindowLabel(NXWidgets::CNxString &appname);

    /**
     * Report of this is a "normal" window or a full screen window.  The
     * primary purpose of this method is so that window manager will know
     * whether or not it show draw the task bar.
     *
     * @return True if this is a full screen window.
     */

    bool isFullScreen(void) const;

    /**
     * Register to receive callbacks when toolbar icons are selected
     */

    void registerCallbacks(IApplicationCallback *callback);

    /**
     * Simulate a mouse click or release on the minimize icon.  This method
     * is only available for automated testing of NxWM.
     *
     * @param click.  True to click; false to release;
     */

#if defined(CONFIG_NXWM_UNITTEST) && !defined(CONFIG_NXWM_TOUCHSCREEN)
    void clickMinimizePosition(bool click);
#endif

    /**
     * Simulate a mouse click or release on the stop icon.  This method
     * is only available for automated testing of NxWM.
     *
     * @param click.  True to click; false to release;
     */

#if defined(CONFIG_NXWM_UNITTEST) && !defined(CONFIG_NXWM_TOUCHSCREEN)
    void clickStopIcon(bool click);
#endif
  };
}

#endif // __cplusplus

#endif // __APPS_GRAPHICS_NXWM_INCLUDECFULLSCREENWINDOW_NXX
