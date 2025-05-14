#ifndef MAINFRAME_H
#define MAINFRAME_H

#include <wx/wx.h>
#include "VpnController.h"

// Custom event that carries log lines 
wxDECLARE_EVENT(wxEVT_VPN_LOG, wxThreadEvent);

class MainFrame : public wxFrame {
public:
	explicit MainFrame(const wxString &title);

	~MainFrame() override;

private:
	// Event handlers
	void OnConnect(wxCommandEvent &evt);

	void OnSendMessage(wxCommandEvent &evt);

	void OnVpnLog(wxThreadEvent &evt);

	void OnClose(wxCloseEvent &event);

	// Helpers
	void StartVpn();

	void StopVpn();

	// Data members
	VpnController *vpn_controller_ = nullptr;


	wxTextCtrl *server_ip_text_ = nullptr;
	wxTextCtrl *port_text_ = nullptr;
	wxTextCtrl *local_ip_text_ = nullptr;
	wxTextCtrl *adaptername_text_ = nullptr;
	wxTextCtrl *subnetmask_text_ = nullptr;
	wxTextCtrl *gateway_text_ = nullptr;
	wxTextCtrl *password_text_ = nullptr;
	wxTextCtrl *log_box_ = nullptr;
	wxTextCtrl *message_box_ = nullptr;

	wxButton *send_message_btn_ = nullptr;
	wxComboBox* mode_text_ = nullptr;  // add here in the class


	// Define style constant
	static constexpr long wxTE_HIDDEN = 0x0800;
};

#endif  // MAINFRAME_H
