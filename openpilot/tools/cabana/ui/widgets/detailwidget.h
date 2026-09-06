#pragma once

#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "tools/cabana/ui/widgets/binaryview.h"
#include "tools/cabana/ui/chart/chartswidget.h"
#include "tools/cabana/ui/widgets/historylog.h"
#include "tools/cabana/ui/widgets/signalview.h"

// a label that elides its text to the available width
class ElidedLabel {
public:
  explicit ElidedLabel(const std::string &text = {});
  void setText(const std::string &text) { text_ = text; }
  void setToolTip(const std::string &tip) { tooltip_ = tip; }
  void draw(float width);

  Observable<> clicked;

private:
  std::string text_, tooltip_;
};

// modal, non-blocking: DetailWidget::draw() polls draw() and applies the result once it returns false
class EditMessageDialog {
public:
  struct Result {
    MessageId msg_id;
    std::string name, node, comment;  // trimmed
    int size;
  };

  EditMessageDialog(const MessageId &msg_id, const std::string &title, int size, float parent_width);
  bool draw();  // false once closed
  bool accepted() const { return accepted_; }
  Result result() const;

private:
  void validateName(const std::string &text);

  MessageId msg_id_;
  std::string original_name_;
  std::string name_edit_;
  std::string node_;
  std::string comment_edit_;
  std::string error_label_;  // empty when the name is valid
  int size_spin_;
  bool ok_enabled_ = true;
  std::string window_title_;
  float width_;
  bool opened_ = false;
  bool accepted_ = false;
  bool closed_ = false;
};

// the content of one message's pane: the header, and the Bits / Signals / Logs views MainWindow docks inside it
class DetailWidget {
public:
  DetailWidget(ChartsWidget *charts, const MessageId &message_id);
  const MessageId &messageId() const { return msg_id_; }
  std::string title() const;  // "id name" for the pane title
  void refresh();
  void drawHeader();   // message name, edit and remove, warnings
  void drawBits();     // heatmap mode and the binary view
  void drawSignals();  // the signal view
  void drawLogs();     // the history log
  void setLogsVisible(bool visible);  // hidden: the log stops reloading, shown: it catches up
  std::string bitsWhatsThis() const;
  std::string signalsWhatsThis() const;

private:
  void drawToolBar();
  void drawHeatmapToolBar();
  void editMsg();
  void updateState(const std::set<MessageId> *msgs = nullptr);

  MessageId msg_id_;
  const char *warning_icon_ = nullptr;
  std::string warning_label_;
  ElidedLabel name_label_;
  bool warning_widget_visible_ = false;
  bool logs_visible_ = false;
  bool action_remove_msg_enabled_ = false;
  bool heatmap_live_ = true;
  std::string heatmap_all_text_ = "All";
  std::unique_ptr<LogsWidget> history_log_;
  std::unique_ptr<BinaryView> binary_view_;
  std::unique_ptr<SignalView> signal_view_;
  ChartsWidget *charts_;
  std::unique_ptr<EditMessageDialog> edit_dlg_;
  Connections connections_;
};

// the center pane until a message is opened
void drawWelcomeWidget();
