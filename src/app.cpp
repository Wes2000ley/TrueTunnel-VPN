#include "App.h"
#include "MainFrame.h"

wxIMPLEMENT_APP(App);

bool App::OnInit() {
	MainFrame* frame = new MainFrame("TrueTunnel VPN");
	frame->SetClientSize(800, 600);
	frame->Centre();
	frame->Show();

	return true;
}
