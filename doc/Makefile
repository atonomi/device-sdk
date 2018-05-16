# vim: set ts=8 sw=8 sts=0 noet:
#
# Copyright (c) 2018 Atonomi
##
.SUFFIXES:
.DEFAULT_GOAL=all
.DELETE_ON_ERROR:
MAKEFLAGS+=--warn-undefined-variables

# pdflatex flags
PDFLTXFLAGS := -file-line-error -interaction=nonstopmode

# Primary TeX source.
TEX_SRC_PRI := atmisdk.tex
# TeX sources.
TEX_SRCS    := $(filter-out $(TEX_SRC_PRI),$(wildcard *.tex))
# Output for PDF targets.
OUT_PDF     := atmisdk.pdf


.PHONY: all
all: $(OUT_PDF)


# Clean all except output pdf
.PHONY: clean
clean:
	latexmk -c


# Clean all outputs
.PHONY: distclean
distclean:
	latexmk -CA


$(OUT_PDF): $(TEX_SRC_PRI) $(TEX_SRCS)
	latexmk -pdf -pdflatex='pdflatex $(PDFLTXFLAGS)' -use-make $<	

