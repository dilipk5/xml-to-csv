import re
import csv
from datetime import datetime

def parse_event_logs(input_file, output_file):
    """
    Parse Windows Security Event logs and extract key fields to CSV.
    
    Args:
        input_file: Path to input file containing event logs
        output_file: Path to output CSV file for results
    """
    
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Split content by "Log Name:" to separate individual events
    # This regex finds "Log Name:" at the start of a line
    events = re.split(r'\n(?=Log Name:)', content)
    events = [e.strip() for e in events if e.strip()]  # Remove empty entries
    
    parsed_events = []
    
    for event in events:
        event_data = {}
        
        # Extract Date
        date_match = re.search(r'Date:\s+(.+?)(?:\n|$)', event)
        if date_match:
            event_data['eventdate'] = date_match.group(1).strip()
        else:
            event_data['eventdate'] = ''
        
        # Extract Computer (Hostname)
        hostname_match = re.search(r'Computer:\s+(.+?)(?:\n|$)', event)
        if hostname_match:
            event_data['hostname'] = hostname_match.group(1).strip()
        else:
            event_data['hostname'] = ''
        
        # Extract User (Account Name from Creator Subject)
        user_match = re.search(r'Creator Subject:.*?Account Name:\s+(.+?)(?:\n|$)', event, re.DOTALL)
        if user_match:
            event_data['user'] = user_match.group(1).strip()
        else:
            event_data['user'] = ''
        
        # Extract Process ID (New Process ID)
        pid_match = re.search(r'New Process ID:\s+(.+?)(?:\n|$)', event)
        if pid_match:
            event_data['processid'] = pid_match.group(1).strip()
        else:
            event_data['processid'] = ''
        
        # Extract Image (New Process Name)
        image_match = re.search(r'New Process Name:\s+(.+?)(?:\n|$)', event)
        if image_match:
            event_data['image'] = image_match.group(1).strip()
        else:
            event_data['image'] = ''
        
        # Extract Process Command Line
        cmdline_match = re.search(r'Process Command Line:\s+(.+?)(?:\n\n|$)', event, re.DOTALL)
        if cmdline_match:
            # Clean up the command line - remove extra whitespace and newlines
            cmdline = cmdline_match.group(1).strip()
            cmdline = ' '.join(cmdline.split())
            event_data['processcommandline'] = cmdline
        else:
            event_data['processcommandline'] = ''
        
        # Extract Hashes (if present)
        hash_match = re.search(r'Hashes:\s+(.+?)(?:\n|$)', event)
        if hash_match:
            event_data['hashes'] = hash_match.group(1).strip()
        else:
            event_data['hashes'] = ''
        
        if any(event_data.values()):  # Only add if we extracted some data
            parsed_events.append(event_data)
    
    # Define CSV columns
    fieldnames = ['eventdate', 'hostname', 'user', 'processid', 'image', 'processcommandline', 'hashes']
    
    # Write to CSV file
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(parsed_events)
    
    # Print to console in CSV format
    print(','.join(fieldnames))
    for event in parsed_events:
        row = []
        for field in fieldnames:
            value = event.get(field, '')
            # Quote fields that contain commas or quotes
            if ',' in value or '"' in value:
                value = f'"{value.replace(chr(34), chr(34)+chr(34))}"'
            row.append(value)
        print(','.join(row))
    
    print(f"\n{'='*80}")
    print(f"Successfully parsed {len(parsed_events)} events")
    print(f"Results saved to: {output_file}")
    print(f"{'='*80}")
    
    return parsed_events


if __name__ == "__main__":
    # Configuration
    input_file = "event_logs.txt"  # Change this to your input file path
    output_file = "parsed_events.csv"  # Change this to your desired output CSV file
    
    try:
        parsed_events = parse_event_logs(input_file, output_file)
        print(f"\nTotal events parsed: {len(parsed_events)}")
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        print("Please create the file and paste your event logs into it.")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
