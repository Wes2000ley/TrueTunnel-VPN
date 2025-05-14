#include "MainFrame.h"

wxDEFINE_EVENT(wxEVT_VPN_LOG, wxThreadEvent);

MainFrame::MainFrame(const wxString& title)
    : wxFrame(nullptr, wxID_ANY, title, wxDefaultPosition, wxSize(420, 560)) {
  wxPanel* panel = new wxPanel(this);
  wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);

  auto AddRow = [&](const wxString& label, wxTextCtrl*& box,
                    const wxString& def = "", long style = 0) {
    sizer->Add(new wxStaticText(panel, wxID_ANY, label), 0, wxALL, 4);
    box = new wxTextCtrl(panel, wxID_ANY, def, wxDefaultPosition,
                         wxDefaultSize, style);
    sizer->Add(box, 0, wxEXPAND | wxALL, 4);
  };


  // Create choices
  wxArrayString mode_choices_s_c;
  mode_choices_s_c.Add("server");
  mode_choices_s_c.Add("client");

  // Create combo box after choices
  mode_text_ = new wxComboBox(panel, wxID_ANY, "server",
                              wxDefaultPosition, wxDefaultSize,
                              mode_choices_s_c, wxCB_READONLY);

  // Add label and box to sizer
  sizer->Add(new wxStaticText(panel, wxID_ANY, "Mode:"), 0, wxALL, 4);
  sizer->Add(mode_text_, 0, wxEXPAND | wxALL, 4);


  AddRow("Server IP:", server_ip_text_);
  AddRow("Port:", port_text_, "5555");
  AddRow("Local IP:", local_ip_text_, "10.0.0.1");
  AddRow("Adapter Name:", adaptername_text_, "TrueTunnel VPN Adapter");
  AddRow("SubnetMask:", subnetmask_text_, "255.255.255.0");
  AddRow("Gateway:", gateway_text_, "10.0.0.2");
  AddRow("Password:", password_text_, "SuperStrongPassword123", wxTE_PASSWORD);

  wxButton* connect_btn = new wxButton(panel, wxID_ANY, "Connect");
  sizer->Add(connect_btn, 0, wxALIGN_CENTER | wxALL, 10);

  log_box_ = new wxTextCtrl(panel, wxID_ANY, "", wxDefaultPosition,
                            wxSize(400, 200),
                            wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
  sizer->Add(log_box_, 1, wxEXPAND | wxALL, 5);

  // Message entry
  message_box_ = new wxTextCtrl(panel, wxID_ANY, "", wxDefaultPosition,
                                wxDefaultSize, 0);
  sizer->Add(message_box_, 0, wxEXPAND | wxALL, 4);

  send_message_btn_ = new wxButton(panel, wxID_ANY, "Send Message");
  sizer->Add(send_message_btn_, 0, wxALIGN_CENTER | wxALL, 4);

  panel->SetSizerAndFit(sizer);
  Centre();

  // Bind events
  Bind(wxEVT_VPN_LOG, &MainFrame::OnVpnLog, this);
  connect_btn->Bind(wxEVT_BUTTON, &MainFrame::OnConnect, this);
  send_message_btn_->Bind(wxEVT_BUTTON, &MainFrame::OnSendMessage, this);
  Bind(wxEVT_CLOSE_WINDOW, &MainFrame::OnClose, this);
}

MainFrame::~MainFrame() {
  StopVpn();
}

void MainFrame::OnConnect(wxCommandEvent&) {
  StartVpn();
}

void MainFrame::OnSendMessage(wxCommandEvent&) {
  if (vpn_controller_ && vpn_controller_->is_running()) {
    std::string msg = message_box_->GetValue().ToStdString();
    if (!msg.empty()) {

      // Special case: /quit
      if (msg == "/quit") {
        vpn_controller_->send_manual_message("/quit");
        vpn_controller_->stop();
        message_box_->Clear();

        auto* e = new wxThreadEvent(wxEVT_VPN_LOG);
        e->SetString("[You] /quit (disconnecting)");
        wxQueueEvent(this, e);

        return;
      }

      // Normal messages
      vpn_controller_->send_manual_message(msg);
      message_box_->Clear();

      auto* e = new wxThreadEvent(wxEVT_VPN_LOG);
      e->SetString("[You] " + wxString::FromUTF8(msg.c_str()));
      wxQueueEvent(this, e);
    }
  }
}



void MainFrame::OnVpnLog(wxThreadEvent& evt) {
  log_box_->AppendText(evt.GetString() + "\n");
  log_box_->ShowPosition(log_box_->GetLastPosition());
}

void MainFrame::OnClose(wxCloseEvent&) {
  StopVpn();
  Destroy();
}

void MainFrame::StartVpn() {
  StopVpn();
  vpn_controller_ = new VpnController;

  vpn_controller_->set_log_callback([this](const std::string& line) {
    auto* e = new wxThreadEvent(wxEVT_VPN_LOG);
    e->SetString(wxString::FromUTF8(line.c_str()));
    wxQueueEvent(this, e);
  });

  std::string mode = mode_text_->GetValue().ToStdString();
  std::string server_ip = server_ip_text_->GetValue().ToStdString();
  int port = std::stoi(port_text_->GetValue().ToStdString());
  std::string local_ip = local_ip_text_->GetValue().ToStdString();
  std::string adapter_name = adaptername_text_->GetValue().ToStdString();
  std::string subnet_mask = subnetmask_text_->GetValue().ToStdString();
  std::string gateway = gateway_text_->GetValue().ToStdString();
  std::string password = password_text_->GetValue().ToStdString();

  vpn_controller_->start(mode, server_ip, port, local_ip, gateway, password,
                         adapter_name, subnet_mask);
}

void MainFrame::StopVpn() {
  if (vpn_controller_) {
    vpn_controller_->stop();
    delete vpn_controller_;
    vpn_controller_ = nullptr;
  }
}
