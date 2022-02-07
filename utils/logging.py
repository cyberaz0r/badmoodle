from time import time
from traceback import format_exc


def exception_logfile(exception):
	filename = 'badmoodle_error_' + str(time()).split('.')[0] + '.txt'
	
	with open(filename, 'w') as exc_file:
		exc_file.write(format_exc())
	
	return filename