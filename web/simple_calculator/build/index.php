<?php

function popCalc() {
    if (isset($_GET['formula'])) {
        $formula = $_GET['formula'];
        if (strlen($formula) >= 150 || preg_match('/[a-z\'"]+/i', $formula)) {
            return 'Try Harder !';
        }
        try {
            eval('$calc = ' . $formula . ';');
            return isset($calc) ? $calc : '?';
        } catch (ParseError $err) {
            return 'Error';
        }
    }
}

$result = popCalc();
echo "Result: " . $result;

?>
