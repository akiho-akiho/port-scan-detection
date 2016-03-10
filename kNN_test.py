import kNN
from numpy import array
import matplotlib.pyplot as plt


def __main__():
	dating_data_mat, dating_labels = kNN.file2matrix('datingTestSet.txt')
	fig = plt.figure()
	ax = fig.add_subplot(111)
	ax.