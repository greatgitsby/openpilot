#pragma once

#include <future>
#include <map>
#include <string>
#include "tools/cabana/analysis/equations.h"
#include "tools/cabana/analysis/transforms.h"
#include "tools/cabana/streams/abstractstream.h"
#include "tools/cabana/utils/util.h"

namespace cabana {
// Runtime data belongs to the session. Views hold immutable snapshots and can close
// without deleting sources or stopping equation evaluation.
struct DisplaySamples {
  std::shared_ptr<const Samples> source;
  Samples values, steps;
  double origin = 0;
  SegmentTree bounds;
};
class AnalysisSession {
public:
  explicit AnalysisSession(AbstractStream &stream);
  ~AnalysisSession();
  std::shared_ptr<const Samples> samples(const std::string &source);
  std::shared_ptr<const Samples> transformed(const std::string &source, const TransformSettings &settings);
  std::shared_ptr<const DisplaySamples> display(const std::string &source, const TransformSettings &settings);
  void setEquations(const std::map<std::string, Equation> &definitions);
  void poll();
  const std::map<std::string, std::string> &diagnostics() const { return diagnostics_; }
  uint64_t revision() const { return revision_; }
  std::vector<std::string> sources() const;
  std::string displayName(const std::string &source) const;
  Observable<double> inspectionChanged;
  void inspect(double time) { if (inspection_time_ != time) { inspection_time_ = time; inspectionChanged(time); } }
private:
  void invalidate();
  struct Evaluation {
    uint64_t revision;
    FieldsSnapshot outputs;
    std::map<std::string, std::string> diagnostics;
  };
  AbstractStream &stream_;
  double inspection_time_ = -1;
  Connections connections_;
  FieldsSnapshot decoded_, derived_;
  struct TransformCache { std::shared_ptr<const Samples> input, output; };
  std::map<std::string, TransformCache> transforms_;
  std::map<std::string, std::shared_ptr<const DisplaySamples>> displays_;
  std::map<std::string, Equation> equations_;
  std::map<std::string, std::string> diagnostics_;
  std::future<Evaluation> job_;
  std::shared_ptr<std::atomic<bool>> cancel_;
  uint64_t revision_ = 1, evaluated_revision_ = 0;
};
}
