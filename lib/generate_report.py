def generate_report(results):
    html = """
        <html>
        <head>
            <style>
                table { 
                    border: 1px solid black;
                    border-collapse: collapse; 
                }
                th, td {
                    border: 1px solid black;
                    padding: 5px;
                    text-align: left;
                    
                }
            </style>
        </head>
        <body>
        <h1>GOOSE Packet Analyzer Report</h1>
    """
    for ied in results:
        html += f"""
            <table>
                <tr>
                    <th>IED Information</th>
                    <th>GOOSE Packet Info</th>
                    <th>Warnings</th>
                </tr>
                <tr>
                <td rowspan='{len(results[ied]['gptype'])}'>
                    Mac Src: {results[ied]['src']} <br>
                    Mac Dst: {results[ied]['dst']}
                </td>
        """
        for gpt in results[ied]['gptype']:
            html += f"""
                
                <td>
                    gocbRef: {results[ied]['gptype'][gpt]['gocbref']} <br>
                    datSet: {results[ied]['gptype'][gpt]['datset']} <br>
                    goID: {results[ied]['gptype'][gpt]['goid']} <br>
                    Packet Count: {results[ied]['gptype'][gpt]['packets']}                    
                </td>
                <td>
            """

            for warning in results[ied]['gptype'][gpt]['warnings']:
                html += f'{warning} <br>'

            html += "</td></tr>"

        html += "</table><br><br>"

    html += '</body></html>'

    return html