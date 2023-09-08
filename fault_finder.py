import tables
import argparse

parser = argparse.ArgumentParser(
    prog='Fault Finder',
    description='Identifies successful faults in hdf file and prints out the addresses of the faulted instructions'
    )
parser.add_argument('hdf_file',
    help='Path to the HDF5 file')
parser.add_argument('target_address',
    help='Instruction address that defines a successful fault when reached')
parser.add_argument('-v', '--verbose',
    help='Print additional information',
    action='store_true'
)
args = parser.parse_args()

try:
    target_address = int(args.target_address, 0)
except ValueError:
    print('Target address needs to be a valid integer')
    exit(1)

try:
    f = tables.open_file(args.hdf_file, 'r')
except OSError:
    print('Unable to find HDF5 file')
    exit(1)

addrs = []

if args.verbose:
    print("Successful Faults:")
for n in f.root.fault._f_iter_nodes('Group'):
    if n.faults.attrs['end_reason'] == f'endpoint {target_address}/1':
        if args.verbose:
            print(f"Experiment: {n._v_name}\tFault address: {hex(n.faults[:][0][0])}")
        addrs.append(n.faults[:][0][0])

if not args.verbose:
    for addr in addrs:
        print(f"{hex(addr)} ", end='')
    print('')

f.close()
