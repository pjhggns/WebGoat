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

    static final String lookup = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890+/";

    public static final char ENCSP = '.'; // display spaces/separators in encoded strings

    static final String asBinStr(int width, int b) {
        String ot = "";
            for (int j=0; j<width; ++j) {
                if ((b & (1 << j)) != 0)
                    ot = "1" + ot;
                else
                    ot = "0" + ot;
            }
            ot += ENCSP;
        return ot;
    }

    @RequestMapping(method = RequestMethod.PUT)
    public
    @ResponseBody
    AttackResult completed(@RequestParam String raw_string) throws IOException {

        // encode the input string treated as a binary number
        // and produce the intermediate calculations for display
        // example:
        // raw input  = "FFF000"
        // rawF       = "FF F0 00"
        // rawBinF    = "FF        F0        00"
        // inpBin     = "1111 1111 1111 0000 0000 0000"
        // binEnc     = "111111 111111 000000 000000"
        // encDec     = "63     63     00     00"
        // encChars   = "/      /      A      A"
        // outChars   = "/  /  A  A"
        // outputO    = "2F @F 41 41"
        // encChars   = "/ / A A"

        // encChURL   = "_  _  A  A"

        StringBuilder raw_SB = new StringBuilder();
        StringBuilder rawF_SB = new StringBuilder();
        StringBuilder rawBinF_SB = new StringBuilder();
        StringBuilder inpBin_SB = new StringBuilder();
        StringBuilder binEnc_SB = new StringBuilder();
        StringBuilder encDec_SB = new StringBuilder();
        StringBuilder encChars_SB = new StringBuilder();
        StringBuilder encCharsF_SB = new StringBuilder();
        StringBuilder outChars_SB = new StringBuilder();
        StringBuilder out_SB = new StringBuilder();
        StringBuilder outputO_SB = new StringBuilder();

        // first, fixup the input for valid hex
        String inp = raw_string.replaceAll("[^A-Fa-f0-9]", "");
        if (inp.length() % 2 != 0)
            inp = inp + "0";
        // TODO: tell user string was changed

        // build the output strings, chunk at a time
        for (int i=0; i<inp.length(); i=i+6) {
            // TODO: This code is horrible
            String strS[] = new String[3];
            String hexS[] = new String[3];
            String decS[] = new String[3];
            int hexN[] = new int[3];

            for (int j = 0; j < 3; ++j) {
                int x = i + j * 2;
                if (inp.length() > x)
                    strS[j] = inp.substring(x, x + 2);
                else
                    strS[j] = "00";
                hexN[j] = Integer.parseInt(strS[j], 16);
                rawF_SB.append(strS[j] + ENCSP);
                inpBin_SB.append(asBinStr(8, hexN[j]) + ENCSP);
            }

            int chunk[] = new int[4];
            chunk[0] = (hexN[0] & 0x00fC) >> 2;
            int x = (hexN[0]);
            int xx = (hexN[0] & 0xfc);
            int xxx = hexN[0] & 0xfc >> 2;
            int xxxx = hexN[0] & 0x00fc ;

            chunk[1] = ((hexN[0] & 0x03) << 4) + ((hexN[1] & 0x00f0) >> 4);
            chunk[2] = ((hexN[1] & 0x0f) << 2) + ((hexN[2] & 0x00c0) >> 6);
            chunk[3] = hexN[2] & 0x3f;

            for (int j = 0; j < chunk.length; ++j) {
                int ch = chunk[j];
                encChars_SB.append(Integer.toString(ch, 16) + ENCSP);
                encDec_SB.append(Integer.toString(ch, 10) + ENCSP);
                String s = lookup.substring(ch, ch+1);
                out_SB.append(s + ENCSP);
                binEnc_SB.append(asBinStr(6, ch) + ENCSP);
            }
        }

        String rawF = rawF_SB.toString();
        String encDec = encDec_SB.toString();
        String encChars = encChars_SB.toString();
        String out = out_SB.toString();
        String inpBin = inpBin_SB.toString();
        String binEnc = binEnc_SB.toString();

        String feedbackArgs = "<br>"
                + "<br>" + "<table border=1 style=font-family:monospace>"
                + "<tr>"
                + "<th>" + "Your input" + "</th>"
                + "<td>" + HtmlUtils.htmlEscape(raw_string) + "</td>"
                + "</tr>"
                + "<tr>"
                + "<th>" + "cleaned" + "</th>"
                + "<td>" + HtmlUtils.htmlEscape(inp) + "</td>"
                + "</tr>"
                + "<tr>"
                + "<th>" + "rawF" + "</th>"
                + "<td>" + rawF + "</td>"
                + "</tr>"
                + "<tr>"
                + "<th>" + "encChars" + "</th>"
                + "<td>" + encChars + "</td>"
                + "</tr>"
                + "<tr>"
                + "<th>" + "encDec" + "</th>"
                + "<td>" + encDec + "</td>"
                + "</tr>"
                + "<tr>"
                + "<th>" + "out" + "</th>"
                + "<td>" + out + "</td>"
                + "</tr>"
                + "<tr>"
                + "<th>" + "inpBin" + "</th>"
                + "<td>" + inpBin + "</td>"
                + "</tr>"
                + "<tr>"
                + "<th>" + "binEnc_SB" + "</th>"
                + "<td>" + binEnc_SB + "</td>"
                + "</tr>"
                + "/table>";


            return trackProgress(success()
                    .feedback("http-basics.encoding.base64")
                    .feedbackArgs(feedbackArgs)
                    .output("")
                    .outputArgs("")
                .build());
    }

    @RequestMapping(method = RequestMethod.GET)
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
