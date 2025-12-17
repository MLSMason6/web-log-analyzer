<!DOCTYPE html>
<html>
<head>
    <title>Log Analyzer</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
    
    <h1>🔍 Web Log Analyzer</h1>
    <p>Upload an Apache or Nginx access log to analyze traffic and detect suspicious activity.</p>

    <form action="analyze.php" method="POST" enctype="multipart/form-data">
        <input type="file" name="logfile" accept=".log,.txt" required>
        <br><br>
        <button type ="submit">Analyze Log</button>
    </form>
    
</body>
</html>