package org.owasp.webgoat.plugin;

import org.owasp.webgoat.assignments.AssignmentEndpoint;
import org.owasp.webgoat.assignments.AssignmentHints;
import org.owasp.webgoat.assignments.AssignmentPath;
import org.owasp.webgoat.assignments.AttackResult;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.util.HtmlUtils;

import java.io.IOException;
import java.net.URLEncoder;

@AssignmentPath("/HttpBasics/encoding")
@AssignmentHints({"http-basics.hints.http_basics_lesson.1"}) // TODO pjh
public class HttpBasics_encoding2 extends AssignmentEndpoint {

    public static final char ENCSP = '.'; // display spaces/separators in encoded strings
    @RequestMapping(method = RequestMethod.GET)
    public
    @ResponseBody
    AttackResult completed(@RequestParam String raw_string) throws IOException {


        String feedbackArgs = "display the input string in base64";
            return trackProgress(success()
                    .feedback("http-basics.reversed")
                    .feedbackArgs(feedbackArgs)
                    .output("http-basics.lesson.success.output")
                    .outputArgs("", "", "")
                .build());
    }

    @RequestMapping(method = RequestMethod.PUT)
    public
    @ResponseBody
    AttackResult completed_put(@RequestParam String raw_string) throws IOException {

        String feedbackArgs = "display the input string in base64";
        return trackProgress(success()
                .feedback("http-basics.encoding.post.feedback")
                .feedbackArgs(feedbackArgs)
                .output("http-basics.lesson.success.output")
                .outputArgs("After trying a few strings, go to the next page" )
                .build());

    }
}
