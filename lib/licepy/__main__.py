# coding: utf-8
import argparse
import getpass
import sys

import cryptography.hazmat.primitives.serialization
import cryptography.x509

from cryptography.hazmat import backends

from truepy import License, LicenseData
from OpenSSL import crypto

from . import createKeyPair, createCertRequest, createCertificate


def main(action, action_arguments, **args):
    try:
        action(*action_arguments, **args)
    except TypeError:
        raise RuntimeError(
            '%s requires additional arguments',
            action.__name__)

    return 0


ACTIONS = {}


def action(f):
    ACTIONS[f.__name__] = f
    return f


@action
def show(license_file, issuer_certificate, license_file_password, **args):
    """show [license file]
    Verifies the signature of a license file and shows information about it.
    You must specify the issuer certificate as --issuer-certificate on the
    command line, and the license file password as --license-file-password.
    """
    with open(license_file, 'rb') as f:
        try:
            license = License.load(f, license_file_password)
        except Exception as e:
            raise RuntimeError('Failed to load license file: %s', e)

    try:
        license.verify(issuer_certificate)
    except Exception as e:
        raise RuntimeError('Failed to verify license: %s', e)

    print('License information')
    print('\tissued by:\t"%s"' % str(license.data.issuer))
    print('\tissued to:\t"%s"' % str(license.data.holder))
    print('\tvalid from:\t%s' % str(license.data.not_before))
    print('\tvalid to:\t%s' % str(license.data.not_after))
    print('\tsubject:\t%s' % (
        '"%s"' % license.data.subject
        if license.data.subject
        else '<none>'))
    print('\tconsumer_type:\t%s' % (
        '"%s"' % license.data.consumer_type
        if license.data.consumer_type
        else '<none>'))
    print('\tinformation:\t%s' % (
        '"%s"' % license.data.info
        if license.data.info
        else '<none>'))
    print('\textra data:\t%s' % (
        '"%s"' % license.data.extra
        if license.data.extra
        else '<none>'))


@action
def cart(cart_file, cart_description, issuer_key, **args):
    """cart [file name] [cart description] 
    Issues a new cart. You must specify the
    issuer private key as --issuer-key on the command line,
    or the new private key as -newkey.
    
    [cart description] must be one command line argument on the form 
    CN=T2,O=T2cloud,... containing cart data fields.
         
        - The cart description of the subject of the request, possible
             arguments are:
               C     - Country name
               ST    - State or province name
               L     - Locality name
               O     - Organization name
               OU    - Organizational unit name
               CN    - Common name
               emailAddress - E-mail address
    """
    try:
        cart_data_parameters = dict(
            (p.strip() for p in i.split('=', 1))
            for i in cart_description.split(','))
    except Exception as e:
        raise RuntimeError(
            'Invalid cart data description (%s): %s',
            cart_data_parameters,
            e)

    careq = createCertRequest(issuer_key, **cart_data_parameters)

    # Default CA certificate is valid for twenty years.
    cacert = createCertificate(careq, (careq, issuer_key), 0, (0, 60 * 60 * 24 * 365 * 20))

    with open(cart_file, 'w') as ca:
        ca.write(
            crypto.dump_certificate(crypto.FILETYPE_PEM, cacert).decode('utf-8')
        )
    print('Creating Certificate Authority certificate in "%s"' % cart_file)


@action
def issue(license_file, license_description, issuer_certificate, issuer_key,
          license_file_password, **args):
    """issue [license file] [digest] [license description]
    Issues a new license and shows information about it. You must specify the
    issuer certificate and key as --issuer-certificate/key on the command line,
    and the license file password as --license-file-password.

    [digest] The environment digest file. 
    
    [license description] must be one command line argument on the form
    not_before=2014-01-01T00:00:00,not_after=2016-01-01T00:00:00,... containing
    license data fields.
    
        - The license of the subject of the request, possible
         arguments are:
           node          - Authorization Number of nodes, default 10000
           not_before    - The timestamp when this license starts to be valid.
           not_after     - The timestamp when this license ceases to be valid.
                           This must be strictly after `not_before`.
           issued        - The timestamp when this license was issued. This
                           defaults to not_before.
           issuer        - The issuer of this certificate. If not specified,
                           UNKNOWN_NAME will be used.
           holder        - The holder of this certificate. If not specified,
                           UNKNOWN_NAME will be used.
           subject       - Free-form string data to associate with the
                           license. This value will be stringified.
           consumer_type - Free-form string data to associate with the
                           license. This value will be stringified.
           info          - Free-form string data to associate with the
                           license. This value will be stringified.
           extra         - Any type of data to store in the license. If this
                           is not a string, it will be JSON serialised.               


    """
    try:
        license_data_parameters = dict(
            (p.strip() for p in i.split('=', 1))
            for i in license_description.split(','))
    except Exception as e:
        raise RuntimeError(
            'Invalid license data description (%s): %s',
            license_description,
            e)

    extra = {'node': license_data_parameters.pop('node', 10000),
             'digests': args.get('digest'),
             'other_extra': license_data_parameters.get('extra')}
    license_data_parameters['extra'] = extra

    try:
        license_data = LicenseData(**license_data_parameters)
    except TypeError as e:
        raise RuntimeError(
            'Incomplete license data description (%s): %s',
            license_description,
            e)

    license = License.issue(issuer_certificate, issuer_key,
                            license_data=license_data)
    with open(license_file, 'wb') as f:
        license.store(f, license_file_password)

    show(license_file, issuer_certificate, license_file_password)


class PasswordAction(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        password = value[-1] if isinstance(value, list) else value
        destination = ' '.join(
            s
            for s in self.dest.split('_')
            if not s == 'password')
        if password == '-':
            password = getpass.getpass(
                'Please enter password for %s:' % destination)

        if namespace.newkey:
            setattr(namespace, self.dest, self.generate_key(
                value[:-1] if isinstance(value, list) else [value], password))
        else:
            setattr(namespace, self.dest, self.get_value(
                value[:-1] if isinstance(value, list) else [value], password))

    def get_value(self, value, password):
        return password

    def generate_key(self, value, password):
        return password


class CertificateAction(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        with open(value, 'rb') as f:
            data = f.read()
        certificate = None
        for file_type in (
                'pem',
                'der'):
            try:
                loader = getattr(
                    cryptography.x509,
                    'load_%s_x509_certificate' % file_type)
                certificate = loader(data, backends.default_backend())
                break
            except:
                pass
        if certificate is None:
            raise argparse.ArgumentError(
                self,
                'Failed to load certificate')
        else:
            setattr(namespace, self.dest, certificate)


class KeyAction(PasswordAction):
    def get_value(self, value, password):
        with open(value[0], 'rb') as f:
            data = f.read()
        try:
            loader = getattr(
                cryptography.hazmat.primitives.serialization,
                'load_pem_private_key')
            return loader(data, password, backends.default_backend())
        except:
            pass
        raise argparse.ArgumentError(
            self,
            'Failed to load key')

    def generate_key(self, value, password):
        cakey = createKeyPair(crypto.TYPE_RSA, 4096)
        with open(value[0], 'w') as capkey:
            capkey.write(
                crypto.dump_privatekey(crypto.FILETYPE_PEM,
                                       cakey,
                                       cipher='AES-256-CFB',
                                       passphrase=password).decode('utf-8')
            )
        print('Creating Certificate Authority private key in "%s"' % value[0])
        print("\033[0;31;40m WARNING (PLEASE SAFEKEEPING): Once you have a certificate and"
              " a private key, you can start issuing licepy. \033[0m")
        return cakey


class ActionAction(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        try:
            action = ACTIONS[value[0]]
        except KeyError:
            raise argparse.ArgumentError(
                self,
                'Unknown action')
        setattr(namespace, self.dest, action)


class DigestAction(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        with open(value, 'r') as f:
            digests = []
            for line in f.readlines():
                digests.append(line.strip('\n'))

        if not digests:
            raise argparse.ArgumentError(
                self,
                'Failed to load certificate')
        else:
            setattr(namespace, self.dest, digests)


parser = argparse.ArgumentParser(
    prog='licepy',
    description='Creates and verifies TrueLicense version 1 licenses',
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog='Actions\n=======\n%s' % (
        '\n\n'.join(action.__doc__ for action in ACTIONS.values())))

parser.add_argument(
    '--issuer-certificate',
    help='The issuer certificate.',
    action=CertificateAction)

parser.add_argument(
    '--issuer-key',
    help='The private key to the certificate and the password; pass "-" as '
         'password to read it from stdin.',
    nargs=2,
    const=None,
    action=KeyAction)

parser.add_argument(
    '--license-file-password',
    help='The password of the license file; pass "-" to read from stdin.',
    const=None,
    action=PasswordAction)

parser.add_argument(
    '--verbose',
    help='Show a stack trace on error.',
    action='store_true')

parser.add_argument(
    '--digest',
    help='The environment digest.',
    action=DigestAction)

parser.add_argument(
    '-newkey',
    help='new a private key.',
    default=False,
    action='store_true')

parser.add_argument(
    'action',
    help='The action to perform; this can be any of %s' % ', '.join(
        ACTIONS.keys()),
    nargs=1,
    action=ActionAction)

parser.add_argument(
    'action_arguments',
    help='Arguments to the action. See below for more information.',
    nargs='*',
    default=[])

try:
    namespace = parser.parse_args()
    sys.exit(main(**vars(namespace)))
except Exception as e:
    try:
        sys.stderr.write('%s\n' % e.args[0] % e.args[1:])
    except:
        sys.stderr.write('%s\n' % str(e))
    if namespace and namespace.verbose:
        import traceback

        traceback.print_exc()
    sys.exit(1)
