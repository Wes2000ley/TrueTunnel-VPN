#include "MainFrame.h"

#include <codecvt>

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

  AddRow("Server Public IP:", public_ip_text_, "only needed on client example: 201.12.21.145");

  sizer->Add(new wxStaticText(panel, wxID_ANY, "Real Adapter (for routing):"), 0, wxALL, 4);
  real_adapter_choice_ = new wxComboBox(panel, wxID_ANY);
  sizer->Add(real_adapter_choice_, 0, wxEXPAND | wxALL, 4);

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
  PopulateRealAdapters();
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

  std::string public_ip = public_ip_text_->GetValue().ToStdString();
  std::string real_adapter =
      real_adapter_choice_->GetSelection() != wxNOT_FOUND
          ? real_adapter_choice_->GetStringSelection().ToStdString()
          : "Ethernet";

  vpn_controller_->start(mode, server_ip, port, local_ip, gateway, password,
                         adapter_name, subnet_mask, public_ip, real_adapter);
}

void MainFrame::PopulateRealAdapters() {
  ULONG out_buf_len = 0;
  GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, nullptr, nullptr, &out_buf_len);

  std::vector<BYTE> buffer(out_buf_len);
  IP_ADAPTER_ADDRESSES* addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

  if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, nullptr, addresses, &out_buf_len) != NO_ERROR)
    return;

  wxArrayString adapter_choices;

  for (IP_ADAPTER_ADDRESSES* adapter = addresses; adapter; adapter = adapter->Next) {
    if (adapter->OperStatus != IfOperStatusUp || adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
      continue;

    std::string name = adapter->FriendlyName ? std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(adapter->FriendlyName) : "Unknown";
    std::string ip;

    for (IP_ADAPTER_UNICAST_ADDRESS* ua = adapter->FirstUnicastAddress; ua; ua = ua->Next) {
      if (ua->Address.lpSockaddr->sa_family == AF_INET) {
        char ip_buf[INET_ADDRSTRLEN] = {};
        sockaddr_in* ipv4 = reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr);
        inet_ntop(AF_INET, &ipv4->sin_addr, ip_buf, sizeof(ip_buf));
        ip = ip_buf;
        break;
      }
    }

    if (!ip.empty()) {
      real_adapters_.push_back({name, ip});
      adapter_choices.Add(wxString::FromUTF8(name.c_str()));
    }
  }
  if (!real_adapter_choice_) return;


  if (real_adapter_choice_) {
    real_adapter_choice_->Clear();
    real_adapter_choice_->Append(adapter_choices);
    if (!adapter_choices.IsEmpty()) {
      real_adapter_choice_->SetSelection(0);
    }
  }
}

void MainFrame::StopVpn() {
  if (vpn_controller_) {
    vpn_controller_->stop();
    delete vpn_controller_;
    vpn_controller_ = nullptr;
  }
}
