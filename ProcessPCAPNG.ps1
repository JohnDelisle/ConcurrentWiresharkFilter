# Define the path to the tshark executable
$tsharkPath = "C:\Program Files\Wireshark\tshark.exe"

# Define the directory containing pcapng files
$directory = "C:\Users\P120504\Downloads\DCcaps"

# Define your custom filters... here's a few I use
# $filter = 'dns.qry.name contains privatelink.invalid'
$timeoutFilter = '(ip.addr == 168.63.129.16 && (dns.flags.response == 0) && ! dns.response_in)'
$invalidFilter = '(dns.qry.name contains privatelink.invalid || dns.resp.name contains privatelink.invalid  || dns.cname contains privatelink.invalid)'
$invalidFromMsFilter = 'ip.src == 168.63.129.16 && dns.resp.name contains privatelink.invalid'
$invalidRespFilter = 'dns.resp.name contains privatelink.invalid'

# set the filter to one of the above
$filter = $invalidRespFilter

# Define the output directory
$outputDir = "$directory\results"

# Ensure the output directory exists
if (-not (Test-Path -Path $outputDir)) {
    New-Item -Path $outputDir -ItemType Directory
}

# Get all pcapng files in the directory
$pcapngFiles = Get-ChildItem -Path $directory -Filter "*.pcapng"

# Define the maximum number of concurrent jobs
$maxConcurrentJobs = 12

# Function to start a new job and manage concurrency
function Start-JobWithThrottle {
    param (
        [string]$filePath,
        [string]$tsharkPath,
        [string]$filter,
        [string]$outputDir
    )

    # Wait until the number of running jobs is below the threshold
    while ((Get-Job -State Running).Count -ge $maxConcurrentJobs) {
        Start-Sleep -Seconds 1
    }

    # Start a new job
    Start-Job -ScriptBlock {
        param ($filePath, $tsharkPath, $filter, $outputDir)
        
        # Extract the file name without extension
        $fileName = [System.IO.Path]::GetFileNameWithoutExtension($filePath)
        # Define the output file path
        $outputFile = Join-Path -Path $outputDir -ChildPath "$fileName-output.txt"

        # Construct the tshark command arguments
        $arguments = @(
            "-r", $filePath
            "-T", "fields"
            "-e", "frame.number"
            "-e", "frame.time"
            "-e", "ip.src"
            "-e", "ip.dst"
            "-e", "_ws.col.Info"
            $filter
        )

        # Start the process and redirect the output to a file
        Start-Process -FilePath $tsharkPath -ArgumentList $arguments -RedirectStandardOutput $outputFile -NoNewWindow -Wait
    } -ArgumentList $filePath, $tsharkPath, $filter, $outputDir
}

# Start a job for each pcapng file with throttling
foreach ($file in $pcapngFiles) {
    Start-JobWithThrottle -filePath $file.FullName -tsharkPath $tsharkPath -filter $filter -outputDir $outputDir
}

# Wait for all jobs to complete
Get-Job | Wait-Job

# Retrieve job results
$jobs = Get-Job
foreach ($job in $jobs) {
    Receive-Job -Job $job
    Remove-Job -Job $job
}

Write-Output "Processing complete. Output files are located in $outputDir."
