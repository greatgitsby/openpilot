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
#include "tools/cabana/ui/widgets/tabbar.h"

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

// the content of a Message pane: the message id tabs, the tool bar and the Bits / Signals / Logs views
class DetailWidget {
public:
  enum View { BitsAndSignals = 0, Bits, Signals, Logs, kViewCount };

  DetailWidget(ChartsWidget *charts);
  void setMessage(const MessageId &message_id);
  const MessageId &messageId() const { return msg_id_; }
  std::string title() const;  // "id name" for the pane title
  void refresh();
  void draw();  // tab bar of message ids, toolbar, warning, the view tabs
  void setVisible(bool visible);  // hidden: the log stops reloading, shown: it catches up
  std::pair<std::string, std::vector<std::string>> serializeMessageIds() const;
  void restoreTabs(const std::string &active_msg_id, const std::vector<std::string> &msg_ids);
  std::vector<std::pair<std::string, ImRect>> helpRects() const;  // HelpOverlay: (whatsThis, rect) of the visible views

  Observable<const MessageId &> openInNewPane;

private:
  void drawToolBar();
  void drawHeatmapToolBar();
  void drawViewTabs();
  void drawBinaryView(float height);  // height 0: the rest of the pane
  void drawSignalView();
  int findOrAddTab(const MessageId& message_id);
  void showTabBarContextMenu(int index);
  void editMsg();
  void updateState(const std::set<MessageId> *msgs = nullptr);
  bool logsShown() const { return visible_ && view_ == View::Logs; }

  MessageId msg_id_;
  const char *warning_icon_ = nullptr;
  std::string warning_label_;
  ElidedLabel name_label_;
  bool warning_widget_visible_ = false;
  TabBar tabbar_;
  View view_ = View::BitsAndSignals;
  bool visible_ = true;
  bool action_remove_msg_enabled_ = false;
  bool heatmap_live_ = true;
  std::string heatmap_all_text_ = "All";
  ImRect binary_view_rect_, signal_view_rect_;  // child window rects of the last draw
  std::unique_ptr<LogsWidget> history_log_;
  std::unique_ptr<BinaryView> binary_view_;
  std::unique_ptr<SignalView> signal_view_;
  ChartsWidget *charts_;
  std::unique_ptr<EditMessageDialog> edit_dlg_;
  Connections connections_;
};

// the Message pane until a message is selected
void drawWelcomeWidget();
