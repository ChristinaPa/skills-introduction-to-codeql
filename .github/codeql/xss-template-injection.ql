/**
 * @name Cross-Site Scripting (XSS) via Flask template rendering
 * @description Detects cases where user input from Flask request parameters
 *              flows into render_template calls, which may lead to XSS if
 *              the template uses the `| safe` filter or autoescape is disabled.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.1
 * @precision medium
 * @id py/custom-xss-template-injection
 * @tags security
 *       external/cwe/cwe-079
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.ApiGraphs

module XssTemplateConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    exists(API::CallNode call |
      call = API::moduleImport("flask").getMember("render_template").getACall()
    |
      sink = call.getArg(_)
      or
      sink = call.getArgByName(_)
    ) and
    // Exclude the first positional argument (the template name)
    not sink = API::moduleImport("flask").getMember("render_template").getACall().getArg(0)
  }
}

module XssTemplateFlow = TaintTracking::Global<XssTemplateConfig>;

import XssTemplateFlow::PathGraph

from XssTemplateFlow::PathNode source, XssTemplateFlow::PathNode sink
where XssTemplateFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This template parameter depends on a $@, which may lead to XSS if rendered with the '| safe' filter.",
  source.getNode(), "user-provided value"
