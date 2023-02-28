import neo4j
import argparse
import re
# import src.db
# import src.secrets-parse

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def get_ntds(file):
    users = []
    with open(file, 'r') as input_list:
        for line in input_list:
            line = line.strip()
            if re.match(".*\..*\\.*:[0-9]{1,8}:[a-e,0-9]{32}:[a-f,0-9]{32}", line):
                # print(f'Match: {line}')
                users.append(line)
            else:
                # print(f'Not a match: {line}')
               pass
    print('finished parsing')
    return users

def get_matches(users):
    hashes = {}
    for i in users:
        hash = i.split(":")[3]
        domain = i.split(":")[0].split('\\')[0]
        user = i.split(":")[0].split('\\')[1]
        full = f'{user}@{domain}'
        if  hash in hashes:
            # print(f'Adding {user} for the hash {hash}\n')
            hashes[hash].append(full)
        else:
            # print(f'Adding new hash: {hash} with the user {user}')
            hashes[hash] = [full]
    return hashes
            
def get_summary(users, hashes, verbose, redacted):
    reused = 0
    users_reused = 0
    uniq_user_pass = 0
    highest_reuse = 1
    for hash in hashes:
        if len(hashes[hash]) > 1:
            users_reused+=len(hashes[hash])
            reused+=1
            if len(hashes[hash]) > highest_reuse:
                highest_reuse = len(hashes[hash])
        else:
            uniq_user_pass+=1
    print(f'{bcolors.HEADER}Summary - Password Reuse{bcolors.ENDC}')
    print(f'{bcolors.BOLD}------------------------{bcolors.ENDC}')
    print(f'       Total users: {len(users)}')
    print(f' Accounts w/ reuse: {users_reused}')
    print(f'Users w/ uniq pwds: {uniq_user_pass}')
    print(f'     Unique hashes: {len(hashes)}')
    print(f'  Reused passwords: {reused}')
    print(f' Most reused count: {highest_reuse}')
    if verbose: 

        print('\n')
        print(f'{bcolors.HEADER}Details - Password Reuse{bcolors.ENDC}')
        print(f'{bcolors.BOLD}------------------------{bcolors.ENDC}')
        for hash in hashes:
            if len(hashes[hash]) > 1:
                if redacted:
                    print(f'{hash[:4]}{"*"*28}{hash[-4:]}')
                else:
                    print(hash)
                for user in hashes[hash]:
                    print(f'    {user}')
                
    print('\n')

    

def connect_db(url, username, password, verbose):
    try:
        try:
            print(f"{bcolors.OKBLUE}[i]{bcolors.ENDC}Attempting to connect to neo4j on {bcolors.BOLD}{bcolors.UNDERLINE}{url}{bcolors.ENDC} - {bcolors.BOLD}{bcolors.UNDERLINE}{username}:{password}{bcolors.ENDC}\n")
            db_conn = neo4j.GraphDatabase.driver(url, auth=(username, password), encrypted=False)
            
            return db_conn
        except Exception:
            print("Couldn't connect to database.")
            # exit()

    except Exception as e:
        print(f"An error occured {e}")
        

def add_hash():
    pass

def add_relationships(db_conn, hashes, verbose, redacted):
    count=0
    for hash in hashes:
        if len(hashes[hash]) > 1:
            if redacted:
                print(f'{bcolors.OKGREEN}[+]{bcolors.ENDC} Creating relationships for the hash: {hash[:4]}{"*"*28}{hash[-4:]}')
            else:
                print(f'{bcolors.OKGREEN}[+]{bcolors.ENDC} Creating relationships for the hash: {hash}')
            print(f'    Reused {len(hashes[hash])} times  -  Attempting to add relationships in BloodHound')
            for user1 in hashes[hash]:
                for user2 in hashes[hash]:
                    user1 = user1.upper()
                    user2 = user2.upper()
                    if user1 != user2:
                        count+=1
                        if verbose:
                            print(f'        {user1} --> {user2}')
                        try:
                            with db_conn.session() as session:
                                query = f'MATCH (n {{name:"{user1}"}}),(m {{name:"{user2}"}}) MERGE (n)-[r1:SharesPassword]->(m) MERGE (m)-[r2:SharesPassword]->(n) return n,m'
                                # print(f'Query: {query}')
                                tx = session.run(query)
                                if verbose:
                                    # print("\n\n{0} successfully added relationship!\n\n".format(tx.single()[0]))
                                    pass
                        except Exception as e:
                            print(e)
                            print (f'           {bcolors.FAIL}[!]{bcolors.ENDC} - could not connect to add the relationship {user1} -> {user2}')
                            continue

        else:
            if verbose:
                if redacted:
                    print(f'{bcolors.OKCYAN}[-]{bcolors.ENDC} No password reuse for the hash: {hash[:4]}{"*"*28}{hash[-4:]}')
                else:
                    print(f'{bcolors.OKCYAN}[-]{bcolors.ENDC} No password reuse for the hash: {hash}')

    if count > 0:
        print(f'\n{bcolors.OKGREEN}[+]{bcolors.ENDC} SharesPassword relationships created: {str(count)}')
    else:
        print(f'\n{bcolors.FAIL}[-]{bcolors.ENDC} No users had shared passwords')
        

def main():
    parser = argparse.ArgumentParser(
        description="Update bloodhound database to show password reuse"
    )
    parser.add_argument(
        "-n",
        "--ntds",
        required=True,
        help="NTDS file that contains all domain users and hashes (Supports the standard format)",
    )
    parser.add_argument(
        "-url",
        "--url",
        required=False,
        help="The neo4j url to auth to (defaults to bolt://localhost:7687)",
        default="bolt://localhost:7687",
    )
    parser.add_argument(
        "-u",
        "--username",
        required=False,
        help="Username to login to neo4j (defaults to neo4j)",
        default="neo4j",
    )
    parser.add_argument(
        "-p",
        "--password",
        required=False,
        help="Password to login to neo4j (defaults to bloodhound)",
        default="BloodHound",
    )
    parser.add_argument(
        "-hash",
        "--hash",
        action="store_true",
        required=False,
        default=False,
        help="Add the \"Hash\" field to users in BloodHound",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        required=False,
        default=False,
        help="verbose",
        action="store_true",
    )
    parser.add_argument(
        "-r",
        "--redact",
        required=False,
        default=False,
        help="Redact hashes from stdout",
        action="store_true",
    )

    args = parser.parse_args()
    users = get_ntds(args.ntds)
    hashes = get_matches(users)  
    get_summary(users, hashes, args.verbose, args.redact)
    db_conn = connect_db(args.url, args.username, args.password, args.verbose)
    add_relationships(db_conn, hashes, args.verbose, args.redact)


if __name__ == "__main__":
    main()