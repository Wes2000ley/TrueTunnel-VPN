// App.h
#ifndef APP_H
#define APP_H

#include <wx/wx.h>


class App : public wxApp {
public:
	virtual bool OnInit() override;
};
// add near the other private methods
void OnVpnLog(wxThreadEvent& evt);

#endif // APP_H
